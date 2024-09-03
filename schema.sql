-- schema.sql
CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT NOT NULL,
    label TEXT,
    timestamp TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    type TEXT CHECK(type IN ('received', 'sent')),
    timestamp TEXT,
    FOREIGN KEY(conversation_id) REFERENCES conversations(id)
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    file_id INTEGER,
    FOREIGN KEY (conversation_id) REFERENCES conversations (id)
    FOREIGN KEY(file_id) REFERENCES files(id)
);

ALTER TABLE messages ADD COLUMN is_read INTEGER DEFAULT 0;

ALTER TABLE messages ADD COLUMN file_id INTEGER;

