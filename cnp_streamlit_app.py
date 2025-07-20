from Crypto.Cipher import AES
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import random
import streamlit as st
import tempfile
import time
import threading

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

# Multithreaded version for multiple flows

def simulate_multiple_flows(num_flows, total_packets, ssthresh_init, variant, loss_rate):
    all_results = []
    threads = []

    def simulate_flow(flow_id):
        loss_packets = sorted(random.sample(range(total_packets), int((loss_rate / 100) * total_packets)))
        results = simulate_tcp_on_data(total_packets, ssthresh_init, loss_packets, variant=variant)
        all_results.append((flow_id, loss_packets, *results))

    for flow_id in range(num_flows):
        thread = threading.Thread(target=simulate_flow, args=(flow_id,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    return sorted(all_results, key=lambda x: x[0])

# Plotting TCP graphs with animation for multiple flows

def plot_multiple_flow_graphs(all_results):
    chart_placeholder = st.empty()
    max_len = max(len(result[2]) for result in all_results)
    for idx in range(max_len):
        fig, ax = plt.subplots(figsize=(10, 6))
        for flow_id, _, time_series, cwnd_series, _, _, _ in all_results:
            if idx < len(time_series):
                ax.step(time_series[:idx+1], cwnd_series[:idx+1], where='post', label=f'Flow {flow_id}')
        ax.set_title('Multi-flow TCP Congestion Window Evolution')
        ax.set_xlabel('Time')
        ax.set_ylabel('CWND')
        ax.grid(True)
        ax.legend()
        chart_placeholder.pyplot(fig)
        time.sleep(0.2)

# Streamlit App

def main():
    st.title("Network Simulation Project - Multi-Flow TCP")

    uploaded_file = st.file_uploader("Upload input text file", type=["txt"])
    if not uploaded_file:
        st.warning("Please upload a text file to continue.")
        return

    data = uploaded_file.read().strip()
    st.text_area("Input Data", data.decode(), height=150)

    packet_size = st.number_input("Enter MSS (Maximum Segment Size) in bytes", min_value=1, value=64)
    ssthresh_init = st.number_input("Enter initial SSTHRESH value", min_value=1, value=8)
    variant = st.selectbox("Select TCP Variant", ["Tahoe", "Reno"])
    error_rate = st.slider("Select Bit Error Rate (%)", 0, 100, 0)
    loss_rate = st.slider("Select packet loss rate (%)", 0, 100, 20)
    num_flows = st.slider("Select number of simultaneous TCP flows", 1, 5, 2)

    key = b"thisisasecretkey"
    encrypted_data = aes_encrypt(data, key)
    stuffed_data = character_stuff(encrypted_data)

    if error_rate > 0:
        stuffed_data = simulate_bit_errors(stuffed_data, error_rate)

    total_packets = (len(stuffed_data) + packet_size - 1) // packet_size

    st.subheader("Encryption & Stuffing")
    st.write(f"Encrypted Data Length: {len(encrypted_data)} bytes")
    st.code(encrypted_data.hex(), language='text')
    st.write(f"Stuffed Data Length: {len(stuffed_data)} bytes")
    st.code(stuffed_data.hex(), language='text')
    st.write(f"Total packets: {total_packets}")

    if st.button("Run Multi-Flow Simulation"):
        all_results = simulate_multiple_flows(num_flows, total_packets, ssthresh_init, variant, loss_rate)

        st.subheader("Multi-Flow CWND Animation")
        plot_multiple_flow_graphs(all_results)

        for flow_id, loss_packets, time_series, cwnd_series, ssthresh_series, ack_series, state_series in all_results:
            st.subheader(f"Flow {flow_id} - TCP Event Table")
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
