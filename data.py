import streamlit as st
from cryptography.fernet import Fernet
import hashlib

# Generate a key (use a static one for demo purposes, or store it securely for real use)
fernet_key = Fernet.generate_key()
cipher = Fernet(fernet_key)

# Initialize session state variables
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'authorized' not in st.session_state:
    st.session_state.authorized = True

# Helper functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_text(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Pages
def home():
    st.title("🔐 Secure Data Encryption System")
    st.write("Choose an action:")
    if st.button("Store New Data"):
        st.session_state.page = "insert"
    if st.button("Retrieve Data"):
        st.session_state.page = "retrieve"

def insert_data():
    st.title("📝 Store Data")
    username = st.text_input("Enter username")
    text = st.text_area("Enter text to encrypt")
    passkey = st.text_input("Enter passkey", type="password")
    if st.button("Encrypt and Store"):
        if username and text and passkey:
            encrypted_text = encrypt_text(text)
            hashed_key = hash_passkey(passkey)
            st.session_state.stored_data[username] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_key
            }
            st.success("Data securely stored!")
        else:
            st.error("Please fill in all fields.")

    if st.button("Back to Home"):
        st.session_state.page = "home"

def retrieve_data():
    if not st.session_state.authorized:
        st.session_state.page = "login"
        return

    st.title("🔓 Retrieve Data")
    username = st.text_input("Enter username")
    passkey = st.text_input("Enter passkey", type="password")

    if st.button("Decrypt"):
        if username in st.session_state.stored_data:
            hashed_input = hash_passkey(passkey)
            stored = st.session_state.stored_data[username]
            if hashed_input == stored["passkey"]:
                decrypted = decrypt_text(stored["encrypted_text"])
                st.success(f"Decrypted Data: {decrypted}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                st.error("Incorrect passkey.")
        else:
            st.error("Username not found.")

        st.warning(f"Failed Attempts: {st.session_state.failed_attempts}/3")
        if st.session_state.failed_attempts >= 3:
            st.session_state.authorized = False
            st.session_state.page = "login"

    if st.button("Back to Home"):
        st.session_state.page = "home"

def login():
    st.title("🔑 Reauthorization Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    # Simple hardcoded login (replace with better logic if needed)
    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state.authorized = True
            st.session_state.failed_attempts = 0
            st.success("Logged in successfully.")
            st.session_state.page = "home"
        else:
            st.error("Invalid credentials.")

# Navigation control
if 'page' not in st.session_state:
    st.session_state.page = "home"

if st.session_state.page == "home":
    home()
elif st.session_state.page == "insert":
    insert_data()
elif st.session_state.page == "retrieve":
    retrieve_data()
elif st.session_state.page == "login":
    login()
