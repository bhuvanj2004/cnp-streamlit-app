import streamlit as st
from Crypto.Cipher import AES
import random
import networkx as nx
import matplotlib.pyplot as plt
import time

# --- Utility Functions ---

def aes_encrypt(data, key):
    pad_len = 16 - (len(data) % 16)
    data += bytes([pad_len]) * pad_len
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data)

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = cipher.decrypt(ciphertext)
    pad_len = decrypted[-1]
    return decrypted[:-pad_len]

def character_stuff(data):
    stuffed = bytearray()
    for byte in data:
        if byte == 0x7E:
            stuffed.extend([0x7D, byte ^ 0x20])
        elif byte == 0x7D:
            stuffed.extend([0x7D, byte ^ 0x20])
        else:
            stuffed.append(byte)
    return bytes(stuffed)

def character_unstuff(data):
    unstuffed = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0x7D:
            i += 1
            unstuffed.append(data[i] ^ 0x20)
        else:
            unstuffed.append(data[i])
        i += 1
    return bytes(unstuffed)

def simulate_routing_path(graph, src, dst):
    try:
        path = nx.shortest_path(graph, source=src, target=dst, weight="weight")
        return path
    except:
        return []

def draw_network(graph, path=[]):
    pos = nx.spring_layout(graph, seed=42)
    edge_labels = nx.get_edge_attributes(graph, "weight")
    fig, ax = plt.subplots()
    nx.draw(graph, pos, with_labels=True, node_color="lightblue", node_size=700, ax=ax)
    nx.draw_networkx_edge_labels(graph, pos, edge_labels=edge_labels, ax=ax)
    if path:
        path_edges = list(zip(path, path[1:]))
        nx.draw_networkx_edges(graph, pos, edgelist=path_edges, edge_color="red", width=2, ax=ax)
    return fig

def simulate_packet_send(msg_bytes, error_rate=0):
    bits = list("".join(f"{byte:08b}" for byte in msg_bytes))
    for _ in range(int(len(bits) * error_rate / 100)):
        idx = random.randint(0, len(bits)-1)
        bits[idx] = '1' if bits[idx] == '0' else '0'
    corrupted = bytearray(int("".join(bits[i:i+8]), 2) for i in range(0, len(bits), 8))
    return bytes(corrupted)

# --- App Initialization ---

st.set_page_config("Encrypted Messenger", layout="wide")
st.title("🔐 Encrypted Messenger with Routing & Congestion Simulation")

if "messages" not in st.session_state:
    st.session_state.messages = []

# Network Topology
rip_graph = nx.DiGraph()
rip_graph.add_weighted_edges_from([
    (0, 1, 1), (1, 2, 1), (2, 3, 1), (0, 3, 5), (1, 3, 3)
])

key = b"thisisasecretkey"

# Layout
col1, col2 = st.columns(2)

with col1:
    st.subheader("🧑 Sender")
    sender_input = st.text_input("Enter message to send")
    src_node = st.selectbox("Sender Node", [0, 1, 2, 3], key="src")
    dst_node = st.selectbox("Receiver Node", [0, 1, 2, 3], key="dst")
    bit_error = st.slider("Simulated Bit Error Rate (%)", 0, 50, 0)
    if st.button("Send"):
        encrypted = aes_encrypt(sender_input.encode(), key)
        stuffed = character_stuff(encrypted)
        routed_path = simulate_routing_path(rip_graph, src_node, dst_node)
        corrupted = simulate_packet_send(stuffed, bit_error)
        timestamp = time.strftime("%H:%M:%S")
        st.session_state.messages.append({
            "from": src_node,
            "to": dst_node,
            "time": timestamp,
            "data": corrupted,
            "path": routed_path
        })

with col2:
    st.subheader("📥 Receiver")
    if len(st.session_state.messages) > 0:
        for idx, msg in enumerate(reversed(st.session_state.messages[-5:])):
            st.markdown(f"**[{msg['time']}] Node {msg['from']} ➝ Node {msg['to']}**")
            fig = draw_network(rip_graph, msg['path'])
            st.pyplot(fig)
            try:
                unstuffed = character_unstuff(msg['data'])
                decrypted = aes_decrypt(unstuffed, key)
                st.success(f"Decrypted Message: {decrypted.decode(errors='ignore')}")
            except:
                st.error("Message corrupted. Could not decrypt properly.")
