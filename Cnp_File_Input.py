
from Crypto.Cipher import AES
import matplotlib.pyplot as plt
import networkx as nx
import numpy as np
import random

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
    plt.figure(figsize=(12, 8))

    plt.subplot(2, 1, 1)
    plt.step(time_series, cwnd_series, where='post', label='CWND', linewidth=2)
    plt.step(time_series, ssthresh_series, where='post', label='SSTHRESH', linestyle='--')
    plt.title('TCP Congestion Window Evolution')
    plt.xlabel('Time')
    plt.ylabel('Window Size')
    plt.legend()
    plt.grid(True)

    plt.subplot(2, 1, 2)
    plt.plot(ack_series, cwnd_series, 'o-', label='ACKs')
    plt.title('ACKs and CWND')
    plt.xlabel('Packet Index')
    plt.ylabel('CWND Size')
    plt.grid(True)
    plt.tight_layout()
    plt.show()

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
    nx.draw(G, pos, with_labels=True, node_size=800, node_color='lightblue', font_size=12)
    nx.draw_networkx_edge_labels(G, pos, edge_labels=labels)
    plt.title('RIP Routing Topology')
    plt.show()

# Main pipeline
def main():
    filename = input("Enter path to the input text file (e.g., input.txt): ")
    try:
        with open(filename, 'r') as f:
            data = f.read().strip().encode()
            print(f"Loaded data from {filename}:")
            print(data.decode())
    except FileNotFoundError:
        print("File not found. Exiting.")
        exit(1)

    key = b"thisisasecretkey"  # 16 bytes

    encrypted_data = aes_encrypt(data, key)
    print(f"\nEncrypted Data Length: {len(encrypted_data)} bytes")
    print("Encrypted data (hex):")
    print(encrypted_data.hex())

    stuffed_data = character_stuff(encrypted_data)
    print(f"\nAfter Character Stuffing: {len(stuffed_data)} bytes")
    print("Stuffed data (hex):")
    print(stuffed_data.hex())

    packet_size = int(input("\nEnter MSS (Maximum Segment Size) in bytes: "))
    total_packets = (len(stuffed_data) + packet_size - 1) // packet_size
    print(f"Total packets to be sent: {total_packets}")

    ssthresh_init = int(input("Enter initial SSTHRESH value: "))

    # Automatically generate random packet losses (e.g., 20% loss rate)
    loss_rate = 0.2
    loss_packets = sorted(random.sample(range(total_packets), int(loss_rate * total_packets)))
    print(f"Randomly generated lost packets: {loss_packets}")

    # Take RIP routing table input
    rip_table = []
    num_nodes = int(input("\nEnter number of nodes for RIP: "))
    for i in range(num_nodes):
        print(f"\nEnter routing entries for Node {i}:")
        num_routes = int(input(f"  Number of destinations from Node {i}: "))
        for _ in range(num_routes):
            dest = int(input("    Destination Node ID: "))
            next_hop = int(input("    Next Hop Node ID: "))
            distance = int(input("    Distance: "))
            rip_table.append({'node': i, 'dest': dest, 'next_hop': next_hop, 'distance': distance})

    # Simulate
    time_series, cwnd_series, ssthresh_series, ack_series, state_series, transitions = simulate_tcp_on_data(
        total_packets, ssthresh_init, loss_packets)

    # Plot everything
    plot_graphs(time_series, cwnd_series, ssthresh_series, ack_series, transitions)
    plot_rip_graph(rip_table)

    # Event table
    print("\n%-10s %-10s %-10s %-20s" % ("Time", "CWND", "SSTHRESH", "State"))
    print("-"*50)
    for t, c, ssth, state in zip(time_series, cwnd_series, ssthresh_series, state_series):
        print("%-10.2f %-10.2f %-10d %-20s" % (t, c, ssth, state))

if __name__ == "__main__":
    main()
