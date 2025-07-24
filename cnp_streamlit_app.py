import streamlit as st
import random
import time
import networkx as nx
import matplotlib.pyplot as plt
from Crypto.Cipher import AES

# Padding and encryption
def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def aes_encrypt_blockwise(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(message)
    encrypted_blocks = []
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        encrypted_blocks.append(cipher.encrypt(block))
    return b"".join(encrypted_blocks)

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    return unpad(decrypted)

# Character stuffing
def character_stuff(data):
    stuffed = bytearray()
    for byte in data:
        if byte in [0x7E, 0x7D]:
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

# Routing (RIP) display
def draw_rip_graph(routing_table):
    G = nx.DiGraph()
    for src, dest, cost in routing_table:
        G.add_edge(src, dest, weight=cost)

    pos = nx.spring_layout(G, seed=42)
    edge_labels = nx.get_edge_attributes(G, 'weight')

    fig, ax = plt.subplots(figsize=(6, 4))
    nx.draw(G, pos, with_labels=True, node_color='lightgreen', node_size=800, ax=ax)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, ax=ax)
    ax.set_title("RIP Routing Topology")
    st.pyplot(fig)

# Main App
def main():
    st.title("📡 Encrypted Messenger with AES, Stuffing & RIP Routing")
    key = b"thisisasecretkey"

    # 1. Message input
    user_input = st.text_area("✉️ Enter Message:", value="Hello from Bhuvan!", height=100)

    # 2. Routing table
    routing_table = [
        (0, 1, 1),
        (1, 2, 1),
        (0, 2, 3)
    ]
    draw_rip_graph(routing_table)

    if st.button("Send Message"):
        st.subheader("🔐 AES Encryption")
        encrypted = aes_encrypt_blockwise(user_input.encode(), key)
        st.code(encrypted.hex(), language='text')

        st.subheader("📦 Character Stuffing")
        stuffed = character_stuff(encrypted)
        st.code(stuffed.hex(), language='text')

        st.subheader("🚀 Message Sent Successfully")

        if st.checkbox("📥 Show Decrypted Output at Receiver"):
            unstuffed = character_unstuff(stuffed)
            decrypted = aes_decrypt(unstuffed, key)
            st.success(decrypted.decode(errors='ignore'))

if __name__ == "__main__":
    main()
