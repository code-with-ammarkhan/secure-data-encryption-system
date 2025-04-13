
# Streamlit Secure Data Storage and Retrieval System
# Author: Ammar Khan

import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# === File and Security Constants ===
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# === Session State Initialization ===
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "theme" not in st.session_state:
    st.session_state.theme = "light"

# === Theme Toggle Setup ===
def set_theme_css():
    if st.session_state.theme == "dark":
        return """
            <style>
            body {
                background-color: #1e1e1e;
                color: white;
            }
            .stButton>button, .stTextInput>div>div>input, .stTextArea>div>textarea {
                background-color: #333;
                color: white;
            }
            </style>
        """
    else:
        return """
            <style>
            body {
                background-color: white;
                color: black;
            }
            .stButton>button, .stTextInput>div>div>input, .stTextArea>div>textarea {
                background-color: #f0f2f6;
                color: black;
            }
            </style>
        """

st.markdown(set_theme_css(), unsafe_allow_html=True)

# === Theme Toggle in Sidebar ===
toggle = st.sidebar.radio("Theme", ["Light Mode", "Dark Mode"], index=0 if st.session_state.theme == "light" else 1)
st.session_state.theme = "light" if toggle == "Light Mode" else "dark"

# === Data Storage Functions ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# === Encryption Helpers ===
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# === Load User Data ===
stored_data = load_data()

# === Animated Stylish Moving Heading (BIG SIZE) ===
st.markdown(
    """
    <style>
    .moving-heading {
        color: black;
        white-space: nowrap;
        overflow: hidden;
        font-size: 42px;
        font-weight: bold;
        animation: moveLeftRight 5s linear infinite alternate;
    }

    @keyframes moveLeftRight {
        0% { transform: translateX(0); }
        100% { transform: translateX(20%); }
    }
    </style>

    <div class="moving-heading">🔐 Secure Data Encryption System</div>
    """,
    unsafe_allow_html=True
)

# === Sidebar Navigation and Logout ===
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
if st.session_state.authenticated_user:
    menu.append("Logout")

choice = st.sidebar.selectbox("Navigation", menu)

# === Home Section ===
if choice == "Home":
    st.subheader("😇 Welcome To The Data Encryption System")

    st.markdown("""
        This system allows you to securely store and retrieve data using encryption.
        - Users store data with a unique passkey.
        - Users decrypt data by providing the correct passkey.
        - Multiple failed login attempts result in lockout.
        - No external database is used.
    """)

# === Register Section ===
elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")
        else:
            st.error("Both fields are required.")

# === Login Section ===
elif choice == "Login":
    st.subheader("🔑 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏱️ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials! Attempts left: {remaining}")

            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔴 Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# === Store Data Section ===
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Key (passphrase)", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved successfully!")
            else:
                st.error("All fields are required.")

# === Retrieve Data Section ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔐 Please login first.")
    else:
        st.subheader("🔍 Retrieve Encrypted Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found.")
        else:
            st.write("Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey To Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted: {result}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data.")

# === Logout Section ===
elif choice == "Logout":
    st.session_state.authenticated_user = None
    st.success("🔓 You have been logged out.")

# === Footer Animation ===
# Footer
st.markdown(
    """
    <style>
    @keyframes slideDown {
        from { transform: translateY(-50px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
    }

    @keyframes gradientText {
        0% { color: rgb(148, 11, 98); }
        100% { color: #00c9ff; }
    }

    .footer {
        text-align: center;
        margin-top: 50px;
        padding: 20px;
        font-size: 18px;
        font-weight: 900;
        animation: slideDown 1.5s ease-out;
    }

    .footer b {
        display: inline-block;
        font-size: 20px;
        font-weight: 900;
        animation: gradientText 2s infinite alternate;
    }
    </style>

    <div class='footer'><b>Developed by ©️ Code With Ammar</b></div>
    """,
    unsafe_allow_html=True
)

