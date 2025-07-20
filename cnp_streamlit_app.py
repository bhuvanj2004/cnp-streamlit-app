


import streamlit as st
from Cnp_File_Input import aes_encrypt, character_stuff, simulate_tcp_on_data, plot_graphs, plot_rip_graph
import random
import tempfile

st.set_page_config(page_title="CNP Simulation", layout="wide")
st.title("🔐 Secure Network Simulation (CNP)")

# File uploader
data_file = st.file_uploader("Upload input data file (text format)", type=["txt"])

if data_file:
    raw_data = data_file.read().decode()
    data = raw_data.strip().encode()
    st.text_area("Loaded Data", raw_data, height=150)

    # AES encryption key
    key = b"thisisasecretkey"  # 16 bytes
    encrypted_data = aes_encrypt(data, key)
    st.write(f"Encrypted Data Length: {len(encrypted_data)} bytes")
    st.code(encrypted_data.hex(), language="text")

    # Character stuffing
    stuffed_data = character_stuff(encrypted_data)
    st.write(f"Stuffed Data Length: {len(stuffed_data)} bytes")
    st.code(stuffed_data.hex(), language="text")

    # TCP Inputs
    packet_size = st.number_input("Enter MSS (Maximum Segment Size) in bytes", min_value=1, value=32)
    ssthresh_init = st.number_input("Enter initial SSTHRESH value", min_value=1, value=64)

    total_packets = (len(stuffed_data) + packet_size - 1) // packet_size
    st.write(f"Total packets to be sent: {total_packets}")

    # Random packet loss
    loss_rate = st.slider("Packet Loss Rate (%)", min_value=0, max_value=100, value=20)
    loss_packets = sorted(random.sample(range(total_packets), int(loss_rate / 100 * total_packets)))
    st.write(f"Randomly generated lost packets: {loss_packets}")

    # RIP input
    num_nodes = st.number_input("Enter number of nodes for RIP", min_value=1, step=1, value=3)
    rip_table = []
    st.subheader("RIP Routing Table")
    for i in range(num_nodes):
        st.markdown(f"**Node {i} Routing Table**")
        num_routes = st.number_input(f"Number of destinations from Node {i}", min_value=0, step=1, key=f"routes_{i}")
        for r in range(num_routes):
            cols = st.columns(3)
            dest = cols[0].number_input(f"Dest ID [{i}-{r}]", key=f"dest_{i}_{r}", step=1)
            next_hop = cols[1].number_input(f"Next Hop [{i}-{r}]", key=f"hop_{i}_{r}", step=1)
            distance = cols[2].number_input(f"Distance [{i}-{r}]", key=f"dist_{i}_{r}", step=1)
            rip_table.append({'node': i, 'dest': int(dest), 'next_hop': int(next_hop), 'distance': int(distance)})

    if st.button("Run Simulation"):
        time_series, cwnd_series, ssthresh_series, ack_series, state_series, transitions = simulate_tcp_on_data(
            total_packets, ssthresh_init, loss_packets)

        st.subheader("TCP Graphs")
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
            plot_graphs(time_series, cwnd_series, ssthresh_series, ack_series, transitions)
            st.pyplot()

        st.subheader("RIP Topology")
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tmpfile:
            plot_rip_graph(rip_table)
            st.pyplot()

        st.subheader("TCP Event Table")
        st.text("%-10s %-10s %-10s %-20s" % ("Time", "CWND", "SSTHRESH", "State"))
        st.text("-"*50)
        for t, c, ssth, state in zip(time_series, cwnd_series, ssthresh_series, state_series):
            st.text("%-10.2f %-10.2f %-10d %-20s" % (t, c, ssth, state))
