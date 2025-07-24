import streamlit as st
from Crypto.Cipher import AES
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import random
import time

# AES encryption/decryption with block-by-block explanation
def aes_encrypt_with_explanation(data, key):
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    cipher = AES.new(key, AES.MODE_ECB)
    blocks = [data[i:i+16] for i in range(0, len(data), 16)]
    encrypted_blocks = []
    st.subheader("🔐 AES Encryption Formula")
    st.latex(r"EncryptedBlock = AES_{Encrypt}(Key, Block)")
    for i, block in enumerate(blocks):
        if i == 0:
            st.markdown(f"**🔎 Block {i+1} Encryption (Detailed):**")
            st.code(f"Input Block (hex): {block.hex()}")
            st.code(f"Key (hex): {key.hex()}")
        encrypted = cipher.encrypt(block)
        encrypted_blocks.append(encrypted)
        if i == 0:
            st.code(f"Encrypted Block (hex): {encrypted.hex()}")
            st.success("✔ AES-128 ECB Encryption Applied on Block 1")
        else:
            st.markdown(f"Block {i+1} Encrypted (hex): `{encrypted.hex()}`")
        time.sleep(0.5)
    return b"".join(encrypted_blocks)

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

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

def simulate_tcp_on_data(total_packets, ssthresh_init, loss_packets, per_node_delay):
    cwnd = 1
    ssthresh = ssthresh_init
    state = 'Slow Start'
    time_series = []
    cwnd_series = []
    ssthresh_series = []
    ack_series = []
    state_series = []
    rtts = []
    time_step = 0
    for i in range(total_packets):
        time_series.append(time_step)
        cwnd_series.append(cwnd)
        ssthresh_series.append(int(ssthresh))
        state_series.append(state)
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
        time_step += per_node_delay * 3  # Simulate RTT delay
        rtts.append(time_step)
    return time_series, cwnd_series, ssthresh_series, ack_series, state_series, rtts

def plot_graphs(time_series, cwnd_series, ssthresh_series, ack_series):
    chart_placeholder = st.empty()
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

def main():
    st.title("🔐 Encrypted Messenger App - Stage 5 (RTT, ACK, Bit Error)")

    uploaded_file = st.file_uploader("📂 Upload input text file", type=["txt"])
    if not uploaded_file:
        st.warning("Please upload a text file to continue.")
        return

    data = uploaded_file.read().strip()
    st.text_area("Input Data", data.decode(), height=150)

    packet_size = st.number_input("📦 MSS (bytes)", min_value=1, value=64)
    ssthresh_init = st.number_input("🌐 Initial SSTHRESH", min_value=1, value=8)
    per_node_delay = st.number_input("🕒 Delay per hop (ms)", min_value=1, value=100)
    error_rate = st.slider("🧪 Bit Error Rate (%)", 0, 100, 0)
    loss_rate = st.slider("❌ Packet Loss Rate (%)", 0, 100, 20)

    key = b"thisisasecretkey"

    encrypted_data = aes_encrypt_with_explanation(data, key)
    stuffed_data = character_stuff(encrypted_data)

    if error_rate > 0:
        stuffed_data = simulate_bit_errors(stuffed_data, error_rate)

    total_packets = (len(stuffed_data) + packet_size - 1) // packet_size
    loss_packets = sorted(random.sample(range(total_packets), int((loss_rate / 100) * total_packets)))

    st.subheader("📊 Transmission Summary")
    st.write(f"Total Packets: {total_packets}")
    st.write(f"Lost Packets: {loss_packets}")
    st.code(stuffed_data.hex(), language='text')

    if st.button("▶ Run Simulation"):
        ts, cwnd, ssthresh, acks, states, rtts = simulate_tcp_on_data(total_packets, ssthresh_init, loss_packets, per_node_delay)
        st.subheader("📈 TCP Graphs")
        plot_graphs(ts, cwnd, ssthresh, acks)

        st.subheader("📋 TCP Event Table")
        st.text("%-10s %-10s %-10s %-10s" % ("Time", "CWND", "SSTHRESH", "State"))
        st.text("-" * 50)
        for t, c, ssth, state in zip(ts, cwnd, ssthresh, states):
            st.text("%-10.2f %-10.2f %-10d %-10s" % (t, c, ssth, state))

        st.subheader("📥 Receiver Output")
        try:
            unstuffed = character_unstuff(stuffed_data)
            decrypted = aes_decrypt(unstuffed, key)
            st.code(decrypted.decode(errors='ignore'), language='text')
        except Exception as e:
            st.error("Decryption failed: " + str(e))

if __name__ == "__main__":
    main()
