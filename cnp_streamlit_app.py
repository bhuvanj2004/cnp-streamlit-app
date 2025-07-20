from Crypto.Cipher import AES
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import random
import streamlit as st
import tempfile

# AES encryption
def aes_encrypt(data, key):
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

# Character stuffing (simple XOR stuffing for illustration)
def character_stuff(data):
    stuffed = bytearray()
    for byte in data:
        if byte == 0x7E:  # FLAG
            stuffed.append(0x7D)
            stuffed.append(byte ^ 0x20)
        elif byte == 0x7D:  # ESCAPE
            stuffed.append(0x7D)
            stuffed.append(byte ^ 0x20)
        else:
            stuffed.append(byte)
    return bytes(stuffed)

# TCP simulation (Tahoe model)
def simulate_tcp_on_data(total_packets, ssthresh_init, loss_packets):
    cwnd = 1
    ssthresh = ssthresh_init
    state = 'Slow Start'
    time_series = []
    cwnd_series = []
    ssthresh_series = []
    ack_series = []
    state_series = []
    transitions = []

    time = 0
    i = 0
    while i < total_packets:
        time_series.append(time)
        cwnd_series.append(cwnd)
        ssthresh_series.append(int(ssthresh))
        state_series.append(state)

        transitions.append((time, cwnd))
        ack_series.append(i)

        if i in loss_packets:
            ssthresh = max(cwnd / 2, 1)
            cwnd = 1
            state = 'Slow Start'
        else:
            if state == 'Slow Start':
                cwnd *= 2
                if cwnd >= ssthresh:
                    state = 'Congestion Avoidance'
            elif state == 'Congestion Avoidance':
                cwnd += 1

        i += 1
        time += 1

    return time_series, cwnd_series, ssthresh_series, ack_series, state_series, transitions

# Plotting TCP graphs
def plot_graphs(time_series, cwnd_series, ssthresh_series, ack_series, transitions):
    fig, ax = plt.subplots(2, 1, figsize=(12, 8))

    ax[0].step(time_series, cwnd_series, where='post', label='CWND', linewidth=2)
    ax[0].step(time_series, ssthresh_series, where='post', label='SSTHRESH', linestyle='--')
    ax[0].set_title('TCP Congestion Window Evolution')
    ax[0].set_xlabel('Time')
    ax[0].set_ylabel('Window Size')
    ax[0].legend()
    ax[0].grid(True)

    ax[1].plot(ack_series, cwnd_series, 'o-', label='ACKs')
    ax[1].set_title('ACKs and CWND')
    ax[1].set_xlabel('Packet Index')
    ax[1].set_ylabel('CWND Size')
    ax[1].grid(True)

    st.pyplot(fig)

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
    st.title("Network Simulation with AES, TCP Tahoe, and RIP Routing")

    uploaded_file = st.file_uploader("Upload input text file", type=["txt"])
    if not uploaded_file:
        st.warning("Please upload a text file to continue.")
        return

    data = uploaded_file.read().strip()
    st.text_area("Input Data", data.decode(), height=150)

    packet_size = st.number_input("Enter MSS (Maximum Segment Size) in bytes", min_value=1, value=64)
    ssthresh_init = st.number_input("Enter initial SSTHRESH value", min_value=1, value=8)
    num_nodes = st.number_input("Enter number of nodes for RIP", min_value=1, value=3)

    # Encrypted and stuffed
    key = b"thisisasecretkey"
    encrypted_data = aes_encrypt(data, key)
    stuffed_data = character_stuff(encrypted_data)
    total_packets = (len(stuffed_data) + packet_size - 1) // packet_size
    loss_packets = sorted(random.sample(range(total_packets), int(0.2 * total_packets)))

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
            total_packets, ssthresh_init, loss_packets)

        st.subheader("TCP Graphs")
        plot_graphs(time_series, cwnd_series, ssthresh_series, ack_series, transitions)

        st.subheader("RIP Topology")
        plot_rip_graph(rip_table)

        st.subheader("TCP Event Table")
        st.text("%-10s %-10s %-10s %-20s" % ("Time", "CWND", "SSTHRESH", "State"))
        st.text("-" * 50)
        for t, c, ssth, state in zip(time_series, cwnd_series, ssthresh_series, state_series):
            st.text("%-10.2f %-10.2f %-10d %-20s" % (t, c, ssth, state))

if __name__ == "__main__":
    main()
