
import hashlib
import os
from functools import wraps
from flask import session, url_for, flash, send_from_directory
import bcrypt
from flask import Flask, request, render_template, redirect, jsonify
from twilio.rest import Client
from flask_socketio import SocketIO
from datetime import datetime
import sqlite3
from flask import send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)
socketio = SocketIO(app)
# Set the secret key for session management
app.secret_key = b'*************************************'
# Twilio credentials
account_sid = '*******************************'
auth_token = '*********************************'
client = Client(account_sid, auth_token)

# Database helper functions
def get_db_connection():
    conn = sqlite3.connect('messages.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_conversations():
    conn = get_db_connection()
    conversations = conn.execute('''
        SELECT c.id, c.sender, c.label, MAX(m.timestamp) as last_message_timestamp,
               (SELECT m.message FROM messages m WHERE m.conversation_id = c.id ORDER BY m.timestamp DESC LIMIT 1) as last_message,
               COUNT(CASE WHEN m.is_read = 0 THEN 1 END) as unread_count
        FROM conversations c
        LEFT JOIN messages m ON c.id = m.conversation_id
        GROUP BY c.id, c.sender, c.label
        ORDER BY last_message_timestamp DESC
    ''').fetchall()
    conn.close()
    return conversations



# # initialise for the new users table
# def init_db():
#     conn = sqlite3.connect('messages.db')
#     with open('schema.sql') as f:
#         conn.executescript(f.read())
#     conn.close()

def get_messages(conversation_id):
    conn = get_db_connection()
    messages = conn.execute('''
        SELECT messages.*, files.filepath 
        FROM messages 
        LEFT JOIN files ON messages.file_id = files.id 
        WHERE messages.conversation_id = ?
    ''', (conversation_id,)).fetchall()
    conn.close()
    return messages




@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory('uploads', filename)

def add_file(conversation_id, filename, filepath):
    conn = get_db_connection()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Insert the file record into the database
    conn.execute('''
        INSERT INTO files (conversation_id, filename, filepath, timestamp) 
        VALUES (?, ?, ?, ?)
    ''', (conversation_id, filename, filepath, timestamp))

    # Get the id of the inserted file record
    file_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]

    conn.commit()
    conn.close()

    return file_id  # Return the file_id to associate with a message

@app.route('/mark_as_read', methods=['POST'])
def mark_as_read():
    conversation_id = request.form.get('conversation_id')
    conn = get_db_connection()
    conn.execute('UPDATE messages SET is_read = 1 WHERE conversation_id = ?', (conversation_id,))
    conn.commit()
    conn.close()
    return 'Messages marked as read', 200


def add_message(sender, message, message_type, file_id=None, is_read=0):
    conn = get_db_connection()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Check if conversation exists
    conversation = conn.execute('SELECT id FROM conversations WHERE sender = ?', (sender,)).fetchone()

    is_new_convo = False
    if not conversation:
        # New conversation, insert it into the database
        conn.execute('INSERT INTO conversations (sender, label, timestamp) VALUES (?, ?, ?)',
                     (sender, '', timestamp))
        conversation_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        is_new_convo = True
    else:
        # Update the existing conversation's timestamp
        conversation_id = conversation['id']
        conn.execute('UPDATE conversations SET timestamp = ? WHERE id = ?',
                     (timestamp, conversation_id))

    # Fetch the actual file path or URL if a file_id is provided
    if file_id:
        file_info = conn.execute('SELECT filepath FROM files WHERE id = ?', (file_id,)).fetchone()
        if file_info:
            message = file_info['filepath']

    # Add message to the messages table
    conn.execute(
        'INSERT INTO messages (conversation_id, message, type, timestamp, file_id, is_read) VALUES (?, ?, ?, ?, ?, ?)',
        (conversation_id, message, message_type, timestamp, file_id, is_read))
    conn.commit()
    conn.close()

    return conversation_id, is_new_convo  # Return whether it's a new conversation



def update_label(conversation_id, new_label):
    with sqlite3.connect('messages.db') as conn:  # Ensure you're using the correct database file name
        cursor = conn.cursor()
        cursor.execute("UPDATE conversations SET label = ? WHERE id = ?", (new_label, conversation_id))
        conn.commit()



@app.route('/incoming', methods=['POST'])
def incoming_message():
    message = request.form.get('Body')
    sender = request.form.get('From')

    # Check for media
    num_media = int(request.form.get('NumMedia', 0))
    if num_media > 0:
        conn = get_db_connection()
        conversation = conn.execute('SELECT id FROM conversations WHERE sender = ?', (sender,)).fetchone()
        conversation_id = conversation['id'] if conversation else None

        for i in range(num_media):
            media_url = request.form.get(f'MediaUrl{i}')
            media_type = request.form.get(f'MediaContentType{i}')

            # Save the media file details and get the file_id
            file_id = add_file(conversation_id, media_type, media_url)

            # Save the message with the actual media URL
            add_message(sender, media_url, 'received', file_id=file_id)

            # Emit the media message to all connected clients
            socketio.emit('new_message', {
                'sender': sender,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'message': media_url,
                'type': 'received'
            })

    if message:
        _, is_new_convo = add_message(sender, message, 'received')

        # Emit the new text message to all connected clients
        socketio.emit('new_message', {
            'sender': sender,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'message': message,
            'type': 'received'
        })

        if is_new_convo:
            # Send the automated reply for a new conversation
            auto_reply = "Hey dear, we received your message, we are not available for the moment, we will contact you soon."
            client.messages.create(
                body=auto_reply,
                from_='whatsapp:+14155238886',
                to=sender
            )
            add_message(sender, auto_reply, 'sent')

            socketio.emit('new_message', {
                'sender': sender,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'message': auto_reply,
                'type': 'sent'
            })

    return 'Message received', 200




@app.route('/respond', methods=['POST'])
def respond():
    sender = request.form.get('to')
    body = request.form.get('body')
    file = request.files.get('file')

    # Handle file upload
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join('uploads', filename)
        file.save(filepath)

        conn = get_db_connection()
        conversation = conn.execute('SELECT id FROM conversations WHERE sender = ?', (sender,)).fetchone()
        conn.close()
        conversation_id = conversation['id'] if conversation else None

        if conversation_id is None:
            return 'Conversation not found', 404

        # Generate the full external URL
        file_url = url_for('uploaded_file', filename=filename, _external=True).replace('127.0.0.1:5000', '7b8a-41-92-18-187.ngrok-free.app')

        # Save the file details to the database and get file_id
        file_id = add_file(conversation_id, filename, file_url)

        # Add the message with the full media URL to the database
        add_message(sender, file_url, 'sent', file_id=file_id)

        # Send the media message using Twilio API
        client.messages.create(
            from_='whatsapp:+14155238886',
            to=sender,
            media_url=[file_url]
        )

        # Emit the media message to update the chat interface in real-time
        socketio.emit('new_message', {
            'sender': sender,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'message': file_url,
            'type': 'sent'
        })
    else:
        # Handle regular text message
        add_message(sender, body, 'sent')

        client.messages.create(
            body=body,
            from_='whatsapp:+14155238886',
            to=sender
        )

        socketio.emit('new_message', {
            'sender': sender,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'message': body,
            'type': 'sent'
        })

    return 'Message sent', 200






@app.route('/')
def index():
    # Redirect to the WhatsApp design page
    return redirect('/login')

@app.route('/table')
def table_view():
    conversations = get_conversations()
    messages = {}
    for convo in conversations:
        convo_id = convo['id']
        msgs = get_messages(convo_id)
        for msg in msgs:
            msg_dict = dict(msg)
            msg_dict['label'] = convo['label']  # Include label from conversation
            if convo['sender'] not in messages:
                messages[convo['sender']] = []
            messages[convo['sender']].append(msg_dict)
    return render_template('messages.html', messages=messages)



@app.route('/update_label', methods=['POST'])
def update_label_route():
    sender = request.form.get('sender')
    label = request.form.get('label')

    # Retrieve the conversation ID using the sender information
    conn = get_db_connection()
    conversation = conn.execute('SELECT id FROM conversations WHERE sender = ?', (sender,)).fetchone()
    conn.close()

    if conversation:
        conversation_id = conversation['id']
        update_label(conversation_id, label)
        return 'Label updated', 200
    else:
        return 'Conversation not found', 404





#configure login
#configuring th login page
def hash_password(password):
    # Generate a salt and hash the password
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed.decode('utf-8')


def get_user(username, password):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if user:
        # Check if the provided password matches the stored hashed password
        stored_hash = user['password']
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8')):
            return user

    return None

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username, password)
        if user:
            session['logged_in'] = True
            return redirect(url_for('whatsapp'))
        else:
            flash('Your username or password is incorrect. Please try again.')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))


#routes for whatssap design
@app.route('/whatsapp')
@login_required
def whatsapp():
    conversations = get_conversations()
    messages = {}
    for convo in conversations:
        convo_id = convo['id']
        msgs = get_messages(convo_id)
        if convo['sender'] not in messages:
            messages[convo['sender']] = []
        for msg in msgs:
            msg_dict = dict(msg)
            if msg_dict['file_id']:  # Check if there's an associated file
                msg_dict['message'] = msg_dict['filepath']  # Show the correct media file path
            messages[convo['sender']].append(msg_dict)
    return render_template('whatsapp_interface.html', messages=messages)



@app.route('/get_conversations', methods=['GET'])
def get_conversations_route():
    try:
        conversations = get_conversations()
        sorted_conversations = sorted(conversations, key=lambda x: x['last_message_timestamp'], reverse=True)

        response = []
        for convo in sorted_conversations:
            response.append({
                'sender': convo['sender'],
                'last_message': convo['last_message'],
                'label': convo['label']  # Include the label in the response
            })

        return jsonify(response), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/get_messages', methods=['GET']) #old
def get_messages_route():
    sender = request.args.get('sender')
    if not sender:
        return jsonify({'error': 'Sender not specified'}), 400

    conn = get_db_connection()
    conversation = conn.execute('SELECT id FROM conversations WHERE sender = ?', (sender,)).fetchone()
    if not conversation:
        conn.close()
        return jsonify({'error': 'No conversation found'}), 404

    conversation_id = conversation['id']

    # Fetch text and media messages
    messages = conn.execute('''
        SELECT messages.*, files.filepath 
        FROM messages 
        LEFT JOIN files ON messages.file_id = files.id 
        WHERE messages.conversation_id = ?
    ''', (conversation_id,)).fetchall()

    conn.close()

    all_items = [dict(msg) for msg in messages]

    for item in all_items:
        if item.get('type') == 'media' or item.get('type') == 'sent_media':
            item['message'] = item['filepath']

        elif not item.get('message'):
            item['message'] = '[Message Undefined]'

    return jsonify(all_items), 200










#login page

# insert the hash logins
# def hash_password(password):
#     return hashlib.sha256(password.encode()).hexdigest()
#
# def hash_password(password):
#     salt = bcrypt.gensalt()
#     hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
#     return hashed.decode('utf-8')
#
# def add_user(username, password):
#     conn = sqlite3.connect('messages.db')
#     cursor = conn.cursor()
#     hashed_password = hash_password(password)
#     cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
#     conn.commit()
#     conn.close()
#
# # Adding a new user
# add_user('******', '******')


# secret_key = os.urandom(24)  # Generates a 24-byte random string
# print("this is the secret key" ,secret_key)  # Print the key to view it

if __name__ == '__main__':
    #init_db()
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True)
