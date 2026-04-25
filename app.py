import streamlit as st
import sqlite3
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

# ---------------- DATABASE ----------------
def get_connection():
    return sqlite3.connect("p2p_auth.db", check_same_thread=False)

def create_tables():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS peers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        peer_name TEXT UNIQUE,
        public_key TEXT
    )
    """)

    conn.commit()
    conn.close()

def add_peer(name, pub):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO peers (peer_name, public_key) VALUES (?,?)", (name, pub))
    conn.commit()
    conn.close()

def get_peer(name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT public_key FROM peers WHERE peer_name=?", (name,))
    res = cur.fetchone()
    conn.close()
    return res[0] if res else None

# ---------------- CRYPTO ----------------
def generate_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key()

    private_pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()

    public_pem = public.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return private_pem, public_pem

def sign(private_pem, msg):
    private = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return private.sign(
        msg.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify(public_pem, msg, sig):
    public = serialization.load_pem_public_key(public_pem.encode())
    try:
        public.verify(
            sig,
            msg.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False

# ---------------- UI ----------------
create_tables()

st.title("🔐 Secure P2P Authentication System")

menu = st.sidebar.selectbox("Menu", ["Register", "Phase1", "Phase2", "Phase3"])

if "session_key" not in st.session_state:
    st.session_state.session_key = None

# -------- Register --------
if menu == "Register":
    st.header("Register Peer")

    name = st.text_input("Peer Name")

    if st.button("Generate Keys"):
        private, public = generate_keys()
        add_peer(name, public)

        st.session_state["private"] = private

        st.success("Peer Registered")
        st.text_area("Private Key", private)
        st.text_area("Public Key", public)

# -------- Phase 1 --------
elif menu == "Phase1":
    st.header("Phase 1: Identity Verification")

    name = st.text_input("Peer Name")
    msg = "authenticate"

    private = st.text_area("Paste Private Key")

    if st.button("Verify"):
        pub = get_peer(name)

        sig = sign(private, msg)
        result = verify(pub, msg, sig)

        if result:
            st.success("Identity Verified")
        else:
            st.error("Verification Failed")

# -------- Phase 2 --------
elif menu == "Phase2":
    st.header("Phase 2: Session Key")

    if st.button("Generate Session Key"):
        st.session_state.session_key = Fernet.generate_key()
        st.success("Session Key Generated")
        st.code(st.session_state.session_key)

# -------- Phase 3 --------
elif menu == "Phase3":
    st.header("Phase 3: Secure Transfer")

    text = st.text_area("Enter message")

    if st.button("Encrypt"):
        key = st.session_state.session_key

        if key:
            f = Fernet(key)
            enc = f.encrypt(text.encode())
            dec = f.decrypt(enc).decode()

            st.subheader("Encrypted")
            st.code(enc)

            st.subheader("Decrypted")
            st.write(dec)
        else:
            st.error("Generate session key first")