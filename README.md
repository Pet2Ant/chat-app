# Secure Chat App

This project is a secure chat application designed to facilitate encrypted real-time communication between clients and a server. It employs end-to-end encryption, SSL/TLS, and robust user authentication to ensure the security and privacy of messages exchanged.

## Project Requirements

### Server Implementation
- **Framework:** Develop a server using a chosen framework (e.g., Flask, Express) capable of handling both REST API and WebSocket communication.
- **Security:** Implement SSL/TLS with self-signed certificates for secure communication.

### Client Implementation
- **Registration & Login:** Create a client application that can register, log in, and send/receive encrypted messages to/from the server.
- **Secure Connection:** Use a self-signed certificate for the client to establish a secure connection.

### Message Encryption
- **End-to-End Encryption:** Implement end-to-end encryption for messages exchanged between the client and server.
- **Encryption Algorithm:** Utilize a secure encryption algorithm (e.g., AES) and ensure the keys are securely exchanged.

### Real-time Chat
- **WebSocket:** Enable real-time communication between clients using WebSocket.
- **Encrypted Messages:** Implement features for sending and receiving encrypted messages in real-time.

### User Authentication and Session Management
- **Authentication:** Develop a secure user authentication system for both REST API and WebSocket connections using tokens.
- **Session Management:** Implement secure session management to handle user sessions on both the server and client sides.
- **Security:** Address issues related to session hijacking or unauthorized access.

### Error Handling
- **Comprehensive Handling:** Implement comprehensive error handling to provide meaningful error messages to users without revealing sensitive information.
- **Secure Logging:** Set up secure logging mechanisms to track and monitor potential security incidents.
- **Security Measures:** Consider common security challenges (e.g., Cross-Site Scripting) and implement measures to prevent them.

### Additional Features
- **Encrypted File Transfers:** Support for encrypted file transfers between clients.
- **User Status Indicators:** Implement user status indicators (online/offline) and typing indicators for enhanced user experience.

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/pet2ant/chat-app.git
   cd secure-chat-app
   ```
2. **Server Setup:**

- Install server dependencies:
```bash
cd server
npm install
```
- Start the server:
```bash
npm start
```

3. **Client Setup**:
- Install client dependencies:
```bash
cd client
npm install
```
- Start the client:
```bash
npm start
```
## Usage
- **Register**: Open the client application and register a new account.
- **Login**: Log in with your credentials.
- **Chat**: Start sending and receiving encrypted messages in real-time.

## Contribution
This application was developed in collaboration with [Chris Kanellopoulos](https://github.com/Ckanel/) and I. We worked concurrently, while developing the app.
