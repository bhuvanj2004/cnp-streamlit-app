from Crypto.Cipher import AES
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import streamlit as st
import random
import time

# AES ECB encryption with first block visualized
def aes_encrypt_visual(data, key):
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    encrypted_blocks = []

    st.markdown("### 🔐 AES ECB Encryption Formula (Visualized for 1st block)")
    st.latex(r"\text{EncryptedBlock} = \text{AES}_{\text{Encrypt}}(\text{Key}, \text{Block})")

    for i, block in enumerate(blocks):
        encrypted = cipher.encrypt(block)
        if i == 0:
            st.code(f"Block {i+1} Input (hex): {block.hex()}\nBlock {i+1} Encrypted (hex): {encrypted.hex()}")
        encrypted_blocks.append(encrypted)
        time.sleep(0.3 if i == 0 else 0.1)

    return b''.join(encrypted_blocks)

# AES decrypt
def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    if len(ciphertext) % 16 != 0:
        ciphertext = ciphertext[:len(ciphertext) - (len(ciphertext) % 16)]
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

# Character Stuffing
def character_stuff(data):
    stuffed = bytearray()
    for byte in data:
        if byte == 0x7E:
            stuffed.append(0x7D)
            stuffed.append(byte ^ 0x20)
        elif byte == 0x7D:
            stuffed.append(0x7D)
            stuffed.append(byte ^ 0x20)
        else:
            stuffed.append(byte)
    return bytes(stuffed)

# Unstuff
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

# Bit error simulation
def simulate_bit_errors(data, error_rate_percent):
    corrupted = bytearray(data)
    num_bits = len(data) * 8
    num_errors = int((error_rate_percent / 100.0) * num_bits)
    for _ in range(num_errors):
        bit_index = random.randint(0, num_bits - 1)
        byte_index = bit_index // 8
        bit_in_byte = bit_index % 8
        corrupted[byte_index] ^= 1 << bit_in_byte
    return bytes(corrupted)

# RIP Routing graph and shortest path
def plot_rip_and_shortest_path(rip_table, source=None, target=None):
    G = nx.DiGraph()
    for entry in rip_table:
        G.add_edge(entry['node'], entry['dest'], weight=entry['distance'])

    pos = nx.spring_layout(G, seed=42)
    labels = nx.get_edge_attributes(G, 'weight')

    fig, ax = plt.subplots()
    nx.draw(G, pos, with_labels=True, node_size=800, node_color='lightblue', ax=ax)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels, ax=ax)
    st.pyplot(fig)

    path = []
    if source is not None and target is not None:
        try:
            path = nx.dijkstra_path(G, source=source, target=target, weight='weight')
            st.success(f"Shortest path from {source} to {target}: {path}")
        except nx.NetworkXNoPath:
            st.error(f"No path from {source} to {target}")
    return path

# Packet transmission simulation with delay
def simulate_transmission(packet_data, path, receiver_container, label=""):
    for i, node in enumerate(path):
        with st.container():
            st.info(f"Packet reached Node {node}")
            time.sleep(0.5)
    time.sleep(0.5)
    receiver_container.markdown(f"**{label} Received:** `{packet_data.decode(errors='ignore')}`")

# Streamlit App
def main():
    st.title("📡 Secure Two-Way Encrypted Messenger with Routing")
    key = b'thisisasecretkey'

    # RIP Routing Setup
    st.subheader("🔀 RIP Routing Table")
    num_nodes = st.number_input("Enter number of nodes", min_value=2, value=4)
    rip_table = []

    for i in range(num_nodes):
        st.markdown(f"**Node {i} routes:**")
        num_routes = st.number_input(f"Routes from Node {i}", min_value=1, max_value=5, key=f"routes_{i}")
        for j in range(num_routes):
            col1, col2, col3 = st.columns(3)
            with col1:
                dest = st.number_input("Dest", key=f"dest_{i}_{j}")
            with col2:
                next_hop = st.number_input("Next Hop", key=f"hop_{i}_{j}")
            with col3:
                dist = st.number_input("Distance", key=f"dist_{i}_{j}")
            rip_table.append({'node': i, 'dest': dest, 'next_hop': next_hop, 'distance': dist})

    st.subheader("🧑‍💻 Two-Way Messenger Input")

    col1, col2 = st.columns(2)
    with col1:
        sender1 = st.text_area("Sender 1 Message")
        src1 = st.number_input("Sender 1 - Source Node", min_value=0, value=0, key="s1_src")
        dst1 = st.number_input("Sender 1 - Destination Node", min_value=0, value=1, key="s1_dst")

    with col2:
        sender2 = st.text_area("Sender 2 Message")
        src2 = st.number_input("Sender 2 - Source Node", min_value=0, value=1, key="s2_src")
        dst2 = st.number_input("Sender 2 - Destination Node", min_value=0, value=0, key="s2_dst")

    error_rate = st.slider("Bit Error Rate (%)", 0, 100, 0)

    if st.button("📨 Start Messaging"):
        # Sender 1
        st.markdown("### 📤 Sender 1 Processing...")
        encrypted1 = aes_encrypt_visual(sender1.encode(), key)
        stuffed1 = character_stuff(encrypted1)
        if error_rate > 0:
            stuffed1 = simulate_bit_errors(stuffed1, error_rate)
        path1 = plot_rip_and_shortest_path(rip_table, src1, dst1)

        receiver1 = st.empty()
        simulate_transmission(stuffed1, path1, receiver1, label="Receiver 1")

        # Sender 2
        st.markdown("### 📤 Sender 2 Processing...")
        encrypted2 = aes_encrypt_visual(sender2.encode(), key)
        stuffed2 = character_stuff(encrypted2)
        if error_rate > 0:
            stuffed2 = simulate_bit_errors(stuffed2, error_rate)
        path2 = plot_rip_and_shortest_path(rip_table, src2, dst2)

        receiver2 = st.empty()
        simulate_transmission(stuffed2, path2, receiver2, label="Receiver 2")

        # Final output
        try:
            unstuffed1 = character_unstuff(stuffed1)
            decrypted1 = aes_decrypt(unstuffed1, key)
            receiver1.code(decrypted1.decode(errors='ignore'))

            unstuffed2 = character_unstuff(stuffed2)
            decrypted2 = aes_decrypt(unstuffed2, key)
            receiver2.code(decrypted2.decode(errors='ignore'))
        except Exception as e:
            st.error(f"Decryption Error: {e}")

if __name__ == "__main__":
    main()
