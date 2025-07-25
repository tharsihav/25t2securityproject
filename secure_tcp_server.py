from socket import *
from threading import Thread, Lock
import sys, os


# ---------------------- Helper Functions ----------------------
def get_user_credentials():
    credentials = {}
    with open("credentials.txt", "r") as f:
        for line in f:
            parts = line.strip().split(maxsplit=1)
            if len(parts) == 2:
                username, password = parts
                credentials[username] = password
    return credentials

def add_new_user(username, password):
    with open("credentials.txt", "a") as file:
        file.write(f"{username} {password}\n")

# ------------------------ Globals ------------------------
if len(sys.argv) != 2:
    print("\n===== Error usage, python3 server.py SERVER_PORT ======\n")
    exit(0)

serverHost = "127.0.0.1"
serverPort = int(sys.argv[1])
serverAddress = (serverHost, serverPort)

activeUsers = {}
activeUsersLock = Lock()
pending_logins = {}
public_keys = {}

# ---------------------- Main funcs ----------------------
def process_message(message, conn, client_address):
    try:
        parts = message.strip().split(' ', 1)
        command = parts[0]
        inputs = parts[1] if len(parts) > 1 else ""

        if command == "LOGIN":
            print(f"login command")
            return handle_login(inputs, conn)

        elif command == "PASSWORD":
            print(f"password command")
            return handle_password(inputs, conn)

        elif command == "LISTUSERS":
            print(f"listusers command")
            username = inputs
            return handle_list_users(username)

        elif command == "DIRECTMESSAGE":
            print(f"dm command")
            sender, recipient, msg = inputs.split(' ', 2)
            return handle_direct_message(sender, recipient, msg)

        elif command == "EXIT":
            print(f"exit command")
            username = inputs
            return handle_exit(conn)
        
        # when user logs in, stored their public key
        elif command == "SETPUBLICKEY": 
            username, publickey_pem = inputs.split(' ', 1)
            return handle_set_pubkey(username, publickey_pem)

        # retrieve public key of user
        elif command == "GETPUBLICKEY": 
            requested_user = inputs
            return handle_get_pubkey(requested_user)

        elif command == "AESKEY_SEND":
            sender, recipient, encrypted_key = inputs.split(' ', 2)
            return handle_aes_key_send(sender, recipient, encrypted_key)

        elif command == "AESKEY_CONFIRM":
            recipient, sender, encrypted_back_hex = inputs.split(' ', 2)
            return handle_aes_key_confirm(sender, recipient, encrypted_back_hex)

        else:
            return "Invalid command"

    except Exception as e:
        print(f"[ERROR] process_message: {e}")
        return "Error processing message"

def handle_login(username, conn):
    user_credentials = get_user_credentials()

    if username in activeUsers:
        return f"'{username}' is already logged in on another device"

    elif username in user_credentials:
        pending_logins[conn] = {"username": username, "state": "waiting_pw"}
        return f"Hello again {username}! Enter password:"

    else:
        pending_logins[conn] = {"username": username, "state": "create_pw"}
        return "New user! Enter password"

def handle_password(password, conn):
    login_state = pending_logins[conn]
    username = login_state["username"]
    state = login_state["state"]

    user_credentials = get_user_credentials()

    if state == "waiting_pw":
        if user_credentials[username] == password:
            activeUsers[username] = conn
            del pending_logins[conn]
            return "Login successful"
        else:
            return "Incorrect password :("

    elif state == "create_pw":
        add_new_user(username, password)
        activeUsers[username] = conn
        del pending_logins[conn]
        return f"User {username} created and logged in!"
    
def handle_set_pubkey(username, publickey_pem):
    #TODO: error checks
    public_keys[username] = publickey_pem
    print(f"{username}'s public key stored: {publickey_pem}")
    return "Public key stored"

def handle_get_pubkey(recipient):
    if recipient in public_keys:
        print(f"user {recipient} public key PEM found: {public_keys[recipient]}")
        return f"REQUESTEDPUBLICKEY {public_keys[recipient]}"
    else:
        return "No public key found"

def handle_aes_key_send(sender, recipient, encrypted_aes_key):
    #send the aes key to the other user
    if recipient not in activeUsers:
        return f"User '{recipient}' is not online."
    recipient_conn = activeUsers[recipient]
    recipient_conn.sendall(f"AESKEY_FROM {sender} {encrypted_aes_key}".encode())
    print(f"AES key sent to {recipient}")
    return ""

def handle_aes_key_confirm(sender, recipient, encrypted_back_hex):
    if sender not in activeUsers:
        return f"User '{sender}' is not online."
    try:
        sender_conn = activeUsers[sender]
        sender_conn.sendall(f"AESKEY_CONFIRMED {recipient} {sender} {encrypted_back_hex}".encode())
        print(f"Key confirmation sent to {sender}")
        return ""
    except Exception as e:
        return f"Error sending key confirmation: {e}"

def handle_list_users(username):
    if not activeUsers:
        return "No users online."
    
    users_list = []
    for user in activeUsers.keys():
        if user == username:
            users_list.append(f"{user} (you)")
        else:
            users_list.append(user)
    
    return "Active users:\n" + "\n".join(users_list)

def handle_direct_message(sender, recipient, message):
    if recipient not in activeUsers:
        print(f"User '{recipient}' is not online.")
        return f"User '{recipient}' is not online."

    try:
        recipient_conn = activeUsers[recipient]
        recipient_conn.sendall(f"DM_FROM {sender} {message}".encode())
        print(f"Message from {sender} sent to {recipient}: {message}")
        return f"Message sent to {recipient}"
    except Exception as e:
        return f"Error sending message: {e}"

def handle_exit(conn):
    username_to_remove = None
    for username, user_conn in activeUsers.items():
        if user_conn == conn:
            username_to_remove = username
            break

    if username_to_remove:
        del activeUsers[username_to_remove]
        return "Logged out successfully."
    return "No active session found."

# ---------------------- Client Thread ----------------------
def client_thread(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            message = data.decode()
            response = process_message(message, conn, addr)
            conn.sendall(response.encode())
    except Exception as e:
        print(f"[ERROR] Client {addr}: {e}")
    finally:
        conn.close()
        print(f"[DISCONNECT] {addr} disconnected.")
        handle_exit(conn)

# ---------------------- Main server loop ----------------------
def start_server():
    serverSocket = socket(AF_INET, SOCK_STREAM)
    serverSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    serverSocket.bind(serverAddress)
    serverSocket.listen(5)

    print("===== TCP server is running =====")
    print("===== Waiting for connections... =====")

    try:
        while True:
            conn, addr = serverSocket.accept()
            thread = Thread(target=client_thread, args=(conn, addr), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\n===== Server is shutting down =====")
    finally:
        serverSocket.close()
        print("===== TCP socket closed =====")

if __name__ == "__main__":
    start_server()