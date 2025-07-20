from Crypto.Cipher import AES
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import random
import streamlit as st
import tempfile
import time

# AES encryption/decryption

def aes_encrypt(data, key):
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    if len(ciphertext) % 16 != 0:
        ciphertext = ciphertext[:len(ciphertext) - (len(ciphertext) % 16)]
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

# Character stuffing/de-stuffing (simple XOR for illustration)
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

# TCP Simulation Variants

def simulate_tcp_on_data(total_packets, ssthresh_init, loss_packets, variant="Tahoe"):
    cwnd = 1
    ssthresh = ssthresh_init
    state = 'Slow Start'
    time_series = []
    cwnd_series = []
    ssthresh_series = []
    ack_series = []
    state_series = []
    transitions = []
    dup_ack = 0

    time_step = 0
    i = 0
    while i < total_packets:
        time_series.append(time_step)
        cwnd_series.append(cwnd)
        ssthresh_series.append(int(ssthresh))
        state_series.append(state)
        transitions.append((time_step, cwnd))
        ack_series.append(i)

        if i in loss_packets:
            ssthresh = max(cwnd / 2, 1)
            cwnd = 1 if variant == "Tahoe" else max(1, ssthresh)
            state = 'Slow Start'
            dup_ack = 0
        else:
            if state == 'Slow Start':
                cwnd *= 2
                if cwnd >= ssthresh:
                    state = 'Congestion Avoidance'
            elif state == 'Congestion Avoidance':
                cwnd += 1

        i += 1
        time_step += 1

    return time_series, cwnd_series, ssthresh_series, ack_series, state_series, transitions

# Plotting TCP graphs with animation

def plot_graphs(time_series, cwnd_series, ssthresh_series, ack_series, transitions):
    chart_placeholder = st.empty()
    table_placeholder = st.empty()

    for idx in range(1, len(time_series) + 1):
        fig, ax = plt.subplots(2, 1, figsize=(10, 6))

        ax[0].step(time_series[:idx], cwnd_series[:idx], where='post', label='CWND', linewidth=2)
        ax[0].step(time_series[:idx], ssthresh_series[:idx], where='post', label='SSTHRESH', linestyle='--')
        ax[0].set_title('TCP Congestion Window Evolution')
        ax[0].set_xlabel('Time')
        ax[0].set_ylabel('Window Size')
        ax[0].legend()
        ax[0].grid(True)

        ax[1].plot(ack_series[:idx], cwnd_series[:idx], 'o-', label='ACKs')
        ax[1].set_title('ACKs and CWND')
        ax[1].set_xlabel('Packet Index')
        ax[1].set_ylabel('CWND Size')
        ax[1].grid(True)

        chart_placeholder.pyplot(fig)
        time.sleep(0.2)

# RIP Routing graph visualization

def plot_rip_graph(rip_table):
    G = nx.DiGraph()
    for entry in rip_table:
        src = entry['node']
        dst = entry['dest']
        weight = entry['distance']
        G.add_edge(src, dst, weight=weight)

    pos = nx.spring_layout(G, seed=42)
    labels = nx.get_edge_attributes(G, 'weight')

    fig, ax = plt.subplots(figsize=(8, 6))
    nx.draw(G, pos, with_labels=True, node_size=800, node_color='lightblue', font_size=12, ax=ax)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels, ax=ax)
    ax.set_title('RIP Routing Topology')

    st.pyplot(fig)

# Streamlit App

def main():
    st.title("Network Simulation Project")

    uploaded_file = st.file_uploader("Upload input text file", type=["txt"])
    if not uploaded_file:
        st.warning("Please upload a text file to continue.")
        return

    data = uploaded_file.read().strip()
    st.text_area("Input Data", data.decode(), height=150)

    packet_size = st.number_input("Enter MSS (Maximum Segment Size) in bytes", min_value=1, value=64)
    ssthresh_init = st.number_input("Enter initial SSTHRESH value", min_value=1, value=8)
    variant = st.selectbox("Select TCP Variant", ["Tahoe", "Reno"])
    num_nodes = st.number_input("Enter number of nodes for RIP", min_value=1, value=3)
    error_rate = st.slider("Select Bit Error Rate (%)", 0, 100, 0)

    key = b"thisisasecretkey"
    encrypted_data = aes_encrypt(data, key)
    stuffed_data = character_stuff(encrypted_data)

    if error_rate > 0:
        stuffed_data = simulate_bit_errors(stuffed_data, error_rate)

    total_packets = (len(stuffed_data) + packet_size - 1) // packet_size

    loss_rate = st.slider("Select packet loss rate (%)", 0, 100, 20)
    loss_packets = sorted(random.sample(range(total_packets), int((loss_rate / 100) * total_packets)))

    st.subheader("Encryption & Stuffing")
    st.write(f"Encrypted Data Length: {len(encrypted_data)} bytes")
    st.code(encrypted_data.hex(), language='text')
    st.write(f"Stuffed Data Length: {len(stuffed_data)} bytes")
    st.code(stuffed_data.hex(), language='text')
    st.write(f"Total packets: {total_packets}")
    st.write(f"Randomly lost packets: {loss_packets}")

    st.subheader("RIP Routing Table")
    rip_table = []
    for i in range(num_nodes):
        st.markdown(f"#### Node {i} Routes")
        num_routes = st.number_input(f"Number of routes for Node {i}", min_value=1, max_value=10, value=2, key=f"routes_{i}")
        for j in range(num_routes):
            col1, col2, col3 = st.columns(3)
            with col1:
                dest = st.number_input(f"Dest Node", key=f"dest_{i}_{j}")
            with col2:
                next_hop = st.number_input(f"Next Hop", key=f"hop_{i}_{j}")
            with col3:
                distance = st.number_input(f"Distance", key=f"dist_{i}_{j}")
            rip_table.append({'node': i, 'dest': dest, 'next_hop': next_hop, 'distance': distance})

    if st.button("Run Simulation"):
        time_series, cwnd_series, ssthresh_series, ack_series, state_series, transitions = simulate_tcp_on_data(
            total_packets, ssthresh_init, loss_packets, variant=variant)

        st.subheader("TCP CWND Animation")
        plot_graphs(time_series, cwnd_series, ssthresh_series, ack_series, transitions)

        st.subheader("RIP Topology")
        plot_rip_graph(rip_table)

        st.subheader("TCP Event Table")
        st.text("%-10s %-10s %-10s %-20s" % ("Time", "CWND", "SSTHRESH", "State"))
        st.text("-" * 50)
        for t, c, ssth, state in zip(time_series, cwnd_series, ssthresh_series, state_series):
            st.text("%-10.2f %-10.2f %-10d %-20s" % (t, c, ssth, state))

        st.subheader("Receiver Output")
        try:
            unstuffed = character_unstuff(stuffed_data)
            decrypted = aes_decrypt(unstuffed, key)
            st.code(decrypted.decode(errors='ignore'), language='text')
        except Exception as e:
            st.error("Error during decryption or unstuffing: " + str(e))

if __name__ == "__main__":
    main()
