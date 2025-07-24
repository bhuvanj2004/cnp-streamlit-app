import streamlit as st
from Crypto.Cipher import AES
import time

# AES Utility Functions
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(data))

def aes_decrypt(data, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(data))

# Character Stuffing (Byte-Level XOR for 0x7E, 0x7D)
def character_stuff(data):
    stuffed = bytearray()
    for byte in data:
        if byte == 0x7E or byte == 0x7D:
            stuffed.append(0x7D)
            stuffed.append(byte ^ 0x20)
        else:
            stuffed.append(byte)
    return bytes(stuffed)

def character_unstuff(data):
    i = 0
    unstuffed = bytearray()
    while i < len(data):
        if data[i] == 0x7D:
            i += 1
            unstuffed.append(data[i] ^ 0x20)
        else:
            unstuffed.append(data[i])
        i += 1
    return bytes(unstuffed)

# Session state for holding the transmitted message
if 'transmitted_data' not in st.session_state:
    st.session_state.transmitted_data = None

# GUI Setup
st.title("📡 Encrypted Messenger Simulator")
mode = st.radio("Select Mode", ["Sender", "Receiver"])

key = b'thisisasecretkey'  # 16 bytes AES key

# SENDER PANEL
if mode == "Sender":
    st.subheader("📤 Sender Panel")
    message = st.text_area("Enter message to send:")
    
    if st.button("Encrypt and Transmit"):
        data_bytes = message.encode()
        encrypted = aes_encrypt(data_bytes, key)
        stuffed = character_stuff(encrypted)
        st.session_state.transmitted_data = stuffed

        st.success("🔐 Message Encrypted & Stuffed. Ready to Receive!")
        st.code(f"Encrypted: {encrypted.hex()}", language='text')
        st.code(f"Stuffed: {stuffed.hex()}", language='text')

# RECEIVER PANEL
elif mode == "Receiver":
    st.subheader("📥 Receiver Panel")

    if st.session_state.transmitted_data is None:
        st.warning("No message transmitted yet.")
    else:
        try:
            received = st.session_state.transmitted_data
            st.code(f"Received Stuffed: {received.hex()}", language='text')

            unstuffed = character_unstuff(received)
            decrypted = aes_decrypt(unstuffed, key)
            st.success("✅ Decryption Successful")
            st.text_area("Decrypted Message", decrypted.decode(errors='ignore'), height=150)
        except Exception as e:
            st.error(f"Decryption Error: {e}")
