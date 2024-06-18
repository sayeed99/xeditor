import streamlit as st
from streamlit_cookies_manager import CookieManager
from streamlit_cookies_manager import EncryptedCookieManager
import uuid
import json
import threading
import requests
import os

# This should be on top of your script
cookies = EncryptedCookieManager(
    # This prefix will get added to all your cookie names.
    # This way you can run your app on Streamlit Cloud without cookie name clashes with other apps.
    prefix="ktosiek/streamlit-cookies-manager/",
    # You should really setup a long COOKIES_PASSWORD secret if you're running on Streamlit Cloud.
    password=os.environ.get("COOKIES_PASSWORD", "My secret password"),
)
if not cookies.ready():
    # Wait for the component to load and send us current cookies.
    st.stop()

# Constants for API access and file paths
live_run = True
credentials_file = "../user_credentials.json"

# API initialization for live or test mode
if live_run:
    endpoint_id = 'zzzuq960tcvv4d'  # Replace with your actual endpoint ID
    api_key = 'FMBONYWTDFBEK5F9Q7W79EEJ29T3S8K95HY6VJBK'  # Replace with your actual API key
    api_url = f'https://api.runpod.ai/v2/{endpoint_id}/runsync'
else:
    api_url = "http://0.0.0.0:5000/xyz"

#Initialize or load session state

if "user" not in st.session_state:
    st.session_state.user = None

def complete(messages):
    headers = {'accept': 'application/json', 'authorization': api_key, 'content-type': 'application/json'}
    data = {"input": {"data": messages}}
    response = requests.post(api_url, headers=headers, json=data)
    return response.json().get("output", {}).get("response", "")

# Lock for thread-safe operations
json_lock = threading.Lock()

def save_messages():
    api_url = 'http://0.0.0.0:5000/upload'
    headers = {'Content-Type': 'application/json'}
    
    with json_lock:
        data = {
            'username': st.session_state.user,
            'filename': st.session_state.code,
            'message': st.session_state.messages
        }

        response = requests.post(api_url, json=data, headers=headers)
        
        if response.status_code == 200:
            print('Messages saved successfully:', response.json())
        else:
            print('Failed to save messages:', response.status_code, response.text)

def load_user_credentials():
    with json_lock:
        if os.path.exists(credentials_file):
            with open(credentials_file, "r") as file:
                return json.load(file)
        else:
            return {}

def save_user_credentials(credentials):
    with json_lock:
        with open(credentials_file, "w") as file:
            json.dump(credentials, file)

def register_user(username, password):
    users = load_user_credentials()
    if username in users:
        return False
    users[username] = password
    save_user_credentials(users)
    return True

def validate_login(username, password):
    users = load_user_credentials()
    return users.get(username) == password

# Check for user session in cookies
if "user" in cookies.keys() and str(cookies['user']):
    cookie_user = cookies.get("user", None)
    if cookie_user:
        st.session_state.user = cookie_user

if st.session_state.user:
    col1, col2 = st.columns([0.85, 0.15])  # Adjust the ratio based on your layout needs
    with col2:
        if st.button("Logout"):
            cookies['user'] = ""
            cookies.save()
            st.session_state.update({"user": None})
            st.rerun()

if st.session_state.user is None:
    menu = ["Login", "Register"]
    choice = st.selectbox("Menu", menu)

    if choice == "Login" and not st.session_state.user:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            if validate_login(username, password):
                st.session_state.user = username
                cookies['user'] = username
                cookies.save()
                st.rerun()
            else:
                st.error("Invalid username or password")
    elif choice == "Register" and not st.session_state.user:
        new_username = st.text_input("New Username")
        new_password = st.text_input("New Password", type="password")
        if st.button("Register"):
            if register_user(new_username, new_password):
                st.session_state.user = new_username
                cookies['user'] = new_username
                cookies.save()
                st.success("You are successfully registered")
                st.rerun()
            else:
                st.error("Username already exists. Try a different username.")

if st.session_state.user:
    st.title(f"AI Therapy Assistant: Anna - Welcome {st.session_state.user}")
    # Application logic here...

    if "messages" not in st.session_state:
        st.session_state.messages = []

    if "code" not in st.session_state:
        st.session_state.code = str(uuid.uuid4())

    if "edit_mode" not in st.session_state:
        st.session_state.edit_mode = False

    if "ai_response" not in st.session_state:
        st.session_state.ai_response = ""

    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # User input
    if prompt := st.chat_input("Hi"):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        ai_response = complete(st.session_state.messages)
        st.session_state.ai_response = ai_response
        st.session_state.edit_mode = False  # Ensure edit mode is off initially
        st.session_state.messages.append({"role": "assistant", "content": ai_response})
        with st.chat_message("assistant"):
            st.markdown(ai_response)
        save_messages()

    # Show the AI response and Update button
    if not st.session_state.edit_mode and st.session_state.ai_response:
        if st.button("Update"):
            st.session_state.edit_mode = True
            st.rerun()  # Rerun the app to reflect the state change immediately

    # Show the edit box and Save Edited Response button if in edit mode
    if st.session_state.edit_mode:
        edited_response = st.text_area("Edit the response below:", value=st.session_state.ai_response, height=150)
        if st.button("Save Edited Response"):
            st.session_state.messages[-1] = {"role": "assistant", "content": edited_response}
            st.session_state.edit_mode = False  # Reset the edit mode
            st.session_state.ai_response = edited_response
            save_messages()  # Save the messages before rerunning
            st.rerun()  # Rerun the app to reflect the state change immediately
