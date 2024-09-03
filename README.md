# <img src="https://github.com/user-attachments/assets/fc540e56-3bce-4a17-93fa-9e7bff1b8e01" width="30" style="vertical-align: middle;"> WhatsApp-Like Messaging System with Flask, JavaScript, and Twilio API

## Features

- **Real-Time Messaging**: Instant message exchange using Socket.IO.
- **Media Support**: Send and receive images and other media types.
- **Twilio Integration**: Handles WhatsApp messaging through Twilio's API.
- **User Interface**: Interactive chat interface with real-time updates.
- **Database**: Stores messages and media in an SQLite database.

## <img src="https://github.com/user-attachments/assets/ddf7ac8e-6d1e-4658-960d-f0e646bb8a66" width="30" style="vertical-align: middle;"> Installation

### Prerequisites

- **Python 3.x**
- **Flask** (Python framework)
- **Twilio Account** (for WhatsApp API integration)
### Setup Backend

1. **Create and activate a virtual environment:**

    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

2. **Install required Python packages:**

    ```bash
    pip install -r requirements.txt
    ```

3. **Set up environment variables:**

    Create a `.env` file in the root directory and add your Twilio credentials and other environment-specific settings:

    ```makefile
    TWILIO_ACCOUNT_SID=your_twilio_account_sid
    TWILIO_AUTH_TOKEN=your_twilio_auth_token
    ```

4. **Run the Flask application:**

   
### Local Development with ngrok

To run the project locally and expose it using ngrok:

1. **Start the Flask server:**
   

2. **Expose your local server using ngrok:**
    ```bash
    ngrok http 5000
    ```
    Note the ngrok URL provided (e.g., `http://your-subdomain.ngrok.io`).

3. **Update Twilio Webhook URLs:**
    - Go to the [Twilio Console](https://www.twilio.com/console).
    - Update the webhook URLs for your messaging service to point to the ngrok URL.

### Clone the Repository

```bash
git clone https://github.com/yourusername/WhatsApp-Like-Messaging-System-with-Flask-JavaScript-and-Twilio-API.git
cd WhatsApp-Like-Messaging-System-with-Flask-JavaScript-and-Twilio-API
