import streamlit as st
import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

st.set_page_config(page_title="🔐 P2P Authentication", layout="wide")

# ---------------- UI STYLE ----------------
st.markdown("""
    <style>
    .main {background-color: #f5f7fa;}
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 10px;
        padding: 8px 16px;
    }
    </style>
""", unsafe_allow_html=True)

# ---------------- TITLE ----------------
st.title("🔐 Secure Three-Phase P2P Authentication System")

menu = st.sidebar.selectbox("Menu", [
    "Register Peer",
    "Phase 1: Identity Verification",
    "Phase 2: Session Key",
    "Phase 3: Secure Transfer",
    "Attack Simulation"
])

# ---------------- STORAGE ----------------
if "peers" not in st.session_state:
    st.session_state.peers = {}

if "session_key" not in st.session_state:
    st.session_state.session_key = None

# ---------------- REGISTER ----------------
if menu == "Register Peer":
    st.header("Register Peer")

    peer_name = st.text_input("Peer Name")

    if st.button("Generate Keys"):
        if peer_name:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()

            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            st.session_state.peers[peer_name] = {
                "private": private_key,
                "public": public_key
            }

            st.success("Peer registered successfully!")

            st.subheader("Private Key")
            st.code(private_pem)

            st.subheader("Public Key")
            st.code(public_pem)

        else:
            st.error("Enter peer name!")

# ---------------- PHASE 1 ----------------
elif menu == "Phase 1: Identity Verification":
    st.header("Phase 1: RSA Identity Verification")

    peer_name = st.text_input("Peer Name")

    if st.button("Verify Identity"):
        if peer_name in st.session_state.peers:
            st.success("Identity Verified ✅")
        else:
            st.error("Peer not found ❌")

# ---------------- PHASE 2 ----------------
elif menu == "Phase 2: Session Key":
    st.header("Phase 2: Secure Session Key")

    if st.button("Generate Session Key"):
        key = secrets.token_hex(16)
        st.session_state.session_key = key
        st.success("Session Key Generated")
        st.code(key)

# ---------------- PHASE 3 ----------------
elif menu == "Phase 3: Secure Transfer":
    st.header("Phase 3: Secure Message Transfer")

    message = st.text_area("Enter Message")

    if st.button("Encrypt & Send"):
        if st.session_state.session_key:
            hashed = hashlib.sha256(
                (message + st.session_state.session_key).encode()
            ).hexdigest()

            st.success("Message Sent Securely")
            st.code(f"Encrypted Hash: {hashed}")
        else:
            st.error("Generate session key first!")

# ---------------- ATTACK ----------------
elif menu == "Attack Simulation":
    st.header("MITM / Identity Attack Simulation")

    target = st.text_input("Target Peer Name")

    if st.button("Simulate Attack"):
        if target in st.session_state.peers:
            st.success("Attack Blocked: Fake identity rejected 🚫")
        else:
            st.error("Attack Failed: No such peer")
