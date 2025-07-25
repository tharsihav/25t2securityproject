import socket
import sys, os
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# Check command line arguments
if len(sys.argv) != 2:
    print("\n===== Error usage, python3 client.py SERVER_PORT ======\n")
    exit(0)

# ----------------- Globals and Setup -----------------
serverHost = "127.0.0.1"
serverPort = int(sys.argv[1])
serverAddress = (serverHost, serverPort)

public_keys = {} 
aes_keys = {} 

# Global variables
tcp_clientSocket = None
clientAlive = False
username = None

# Shared response tracking
last_response = None
response_lock = threading.Lock()
# ---------------------- TCP Helpers ----------------------
def send_tcp_message(message):
    global last_response
    try:
        with response_lock:
            last_response = None # resettign last respsoen
        tcp_clientSocket.sendall(message.encode())

        timeout = time.time() + 3  # wait fro updated resposne
        while time.time() < timeout:
            with response_lock:
                if last_response is not None:
                    return last_response
            time.sleep(0.05) 
        return "No response from server."
    except Exception as e:
        return f"Error sending message: {e}"

def listen_for_incoming_messages():
    global last_response
    while True:
        try:
            message = tcp_clientSocket.recv(1024).decode()
            if not message:
                break

            if message.startswith("DM_FROM"):
                _, sender, encrypted_hex = message.split(' ', 2)
                handle_dm_from(sender, encrypted_hex)

            elif message.startswith("AESKEY_FROM"):
                _, sender, encrypted_key_hex = message.split(' ', 2)
                handle_aes_key_accept(sender, encrypted_key_hex)
            
            elif message.startswith("AESKEY_CONFIRMED"):
                _, recipient, sender, encrypted_back_hex = message.split(' ', 3)
                handle_aes_key_confirmed(sender, recipient, encrypted_back_hex)

            else:
                with response_lock:
                    last_response = message
        except:
            break

# ------------------------- RSA ----------------------------
def generate_rsa_keypair():
    # created a unique rsa key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    #serialise the key with PEM
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

def load_public_key(pem_data):
    # reconvert PEm data
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_public_key(pem_data.encode())

def handle_aes_key_accept(sender, encrypted_key_hex):
    encrypted_key = bytes.fromhex(encrypted_key_hex)
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    aes_keys[sender] = aes_key

    if sender not in public_keys:
        tcp_clientSocket.sendall(f"GETPUBLICKEY {sender}".encode())
    send_aes_key_confirmation(sender, aes_key)
    print(f"AES key recieved from {sender}",end="", flush=True)
    return

def send_aes_key_confirmation(sender, aes_key):
    try:
        sender_pub_key_pem = public_keys[sender]
        sender_pub_key = serialization.load_pem_public_key(sender_pub_key_pem.encode()) 
    except Exception as e:
        return

    encrypted_back = sender_pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_back_hex = encrypted_back.hex()
    tcp_clientSocket.sendall(f"AESKEY_CONFIRM {username} {sender} {encrypted_back_hex}".encode())


def handle_aes_key_confirmed(sender, recipient, encrypted_back_hex):
    encrypted_back = bytes.fromhex(encrypted_back_hex)
    decrypted_back = private_key.decrypt(
        encrypted_back,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    if decrypted_back == aes_keys[sender]:
        print(f"\nSession key with {recipient} successfully confirmed.\n> ", end="")
    else:
        print(f"\nWARNING: Session key mismatch with {recipient}!\n> ", end="")
    return

# ---------------------- Main Functions ----------------------
def connect_to_server():
    global tcp_clientSocket, clientAlive, private_key, public_key, publickey_pem
    try:
        tcp_clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_clientSocket.connect(serverAddress)
        clientAlive = True

        # generate keys at connection/startup
        private_key, public_key = generate_rsa_keypair()
        publickey_pem = serialize_public_key(public_key)

        # listener thread
        listener_thread = threading.Thread(target=listen_for_incoming_messages, daemon=True)
        listener_thread.start()
        return True
    
    except Exception as e:
        print(f"===== Failed to connect to server: {e} =====")
        return False

def login(username_input):
    global username
    response = send_tcp_message("LOGIN " + username_input)
    if "Enter password" in response:
        print(response, end=' ')
        while True:
            password = input().strip()
            if not password:
                print("Please enter a non-empty password.")
                continue
            if " " in password:
                print("Please enter a password without spaces")
                continue
            response = send_tcp_message(f"PASSWORD {password}")
            print(response)
            if "Login successful" in response or "logged in" in response:
                username = username_input
                print("Welcome to the chatapp!")
                # send server newly generated public key after login/register
                send_tcp_message(f"SETPUBLICKEY {username} {publickey_pem}")

                listener_thread = threading.Thread(target=listen_for_incoming_messages, daemon=True)
                listener_thread.start()
                break
            elif "Incorrect password" in response:
                return
            else:
                print("Unexpected response, aborting login")
                return
    else:
        print(response)

def list_users():
    global username
    response = send_tcp_message(f"LISTUSERS {username}")
    print(response)

def start_message_session(recipient):
    response = send_tcp_message(f"GETPUBLICKEY {recipient}")
    if response.startswith("REQUESTEDPUBLICKEY"):
        pubkey_pem = response.replace("REQUESTEDPUBLICKEY ", "", 1)
        public_keys[recipient] = pubkey_pem

        # then generate aes key and sent that through 
        session_aes_key = get_aes_key(recipient)
        if session_aes_key is None:
            return # alr have session key 
        else:
            # de serialise public ket
            recipient_public_key = serialization.load_pem_public_key(pubkey_pem.encode())
            # encrypt the wes key
            encrypted_aes_key = recipient_public_key.encrypt(
                session_aes_key,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )

            print(f"Generating and sending AES key to {recipient}")
            tcp_clientSocket.sendall(f"AESKEY_SEND {username} {recipient} {encrypted_aes_key.hex()}".encode())
            # send_tcp_message(f"AESKEY_SEND {username} {recipient} {encrypted_aes_key.hex()}")
    else:
        print(response)
        return None

def get_aes_key(recipient):
    if recipient in aes_keys:
        return  None # Already have a session key'
    else:
        aes_key = AESGCM.generate_key(bit_length=256)
        aes_keys[recipient] = aes_key
        return aes_key
        
def direct_message(recipient, message):
    global username
    # check that aes is there
    if recipient not in aes_keys:
        print(f"[WARNING] No AES session with {recipient}. Establish a key first.")
        return

    aes_key = aes_keys[recipient]
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # TODO: explain 96-bit nonce 
    ciphertext = aesgcm.encrypt(nonce, message.encode(), None)

    encrypted_hex = (nonce + ciphertext).hex()

    msg = f"DIRECTMESSAGE {username} {recipient} {encrypted_hex}"
    response = send_tcp_message(msg)
    print(response)

def exit_forum():
    global username, clientAlive
    response = send_tcp_message(f"EXIT {username}")
    print(response)
    if "Logged out successfully." in response:
        print(f"You have been logged out! Goodbye '{username}' :(")
        username = None
        clientAlive = False
    else:
        print("Error logging out.")

def handle_dm_from(sender, encrypted_hex):
    if sender not in aes_keys:
        print(f"\n[WARNING] No AES key for {sender}, cannot decrypt: {encrypted_hex}\n> ", end="")
        return

    aes_key = aes_keys[sender]
    aesgcm = AESGCM(aes_key)
    data = bytes.fromhex(encrypted_hex)
    nonce, ciphertext = data[:12], data[12:]
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None).decode()
        print(f"\nDM_FROM {sender} (decrypted): {plaintext}\n> ", end="")
    except InvalidTag:
        print(f"\n [SECURITY WARNING] Tampering detected in message from {sender} (MITM suspected)\n> ", end="")


def parse_user_input(user_input):
    if not user_input:
        return

    user_input = user_input.strip()
    command = user_input[:3]
    args = user_input[3:].strip()

    if command == "LST":
        if args:
            print("===== Usage: LST =====")
            ##display_menu()()
            return
        list_users()

    elif command == "KEY":
        if not args:
            print("===== Usage: KEY <username> =====")
            ##display_menu()()
            return
        start_message_session(args)

    elif command == "MSG":
        subparts = args.split(' ', 1)
        if len(subparts) < 2:
            print("===== Usage: MSG <recipient> <message> =====")
            ##display_menu()()
            return
        recipient, message = subparts
        direct_message(recipient, message)

    elif command == "XIT":
        if args:
            print("===== Usage: XIT =====")
            ##display_menu()()
            return
        exit_forum()

    else:
        print("Invalid command")
        ##display_menu()()

def main():
    global clientAlive, tcp_clientSocket

    print("===== Welcome to the Chat Application =====")

    if not connect_to_server():
        print("Failed to connect to server. Exiting...")
        return

    try:
        while clientAlive:
            if username is None:
                user_input = input("Enter username: ").strip()
                if not user_input:
                    print("Username cannot be empty.")
                    continue
                login(user_input)
            else:
                user_input = input("> ")
                parse_user_input(user_input)
    except KeyboardInterrupt:
        print("\nExiting chat application...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if tcp_clientSocket:
            tcp_clientSocket.close()

if __name__ == "__main__":
    main()
