import streamlit as st
import sqlite3
import pandas as pd
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.fernet import Fernet

DB_NAME = "p2p_auth.db"

# ---------------- DATABASE ----------------
def get_connection():
    return sqlite3.connect(DB_NAME, check_same_thread=False)

def create_tables():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS peers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        peer_name TEXT UNIQUE,
        public_key TEXT,
        created_at TEXT
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        peer_name TEXT,
        phase TEXT,
        status TEXT,
        details TEXT,
        timestamp TEXT
    )
    """)

    conn.commit()
    conn.close()

def add_peer(peer_name, public_key):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT OR REPLACE INTO peers (peer_name, public_key, created_at)
    VALUES (?, ?, ?)
    """, (peer_name, public_key, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_peer(peer_name):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT public_key FROM peers WHERE peer_name=?", (peer_name,))
    result = cur.fetchone()
    conn.close()
    return result[0] if result else None

def add_log(peer_name, phase, status, details):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("""
    INSERT INTO logs (peer_name, phase, status, details, timestamp)
    VALUES (?, ?, ?, ?, ?)
    """, (peer_name, phase, status, details, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_logs():
    conn = get_connection()
    df = pd.read_sql_query("SELECT * FROM logs ORDER BY id DESC", conn)
    conn.close()
    return df

# ---------------- CRYPTO ----------------
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return private_pem, public_pem

def sign_message(private_pem, message):
    private_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return private_key.sign(
        message.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )

def verify_signature(public_pem, message, signature):
    public_key = serialization.load_pem_public_key(public_pem.encode())
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def generate_hmac_key():
    return Fernet.generate_key()

def encrypt_message(key, message):
    return Fernet(key).encrypt(message.encode())

def decrypt_message(key, encrypted):
    return Fernet(key).decrypt(encrypted).decode()

def generate_mac(key, message):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message.encode())
    return h.finalize()

def verify_mac(key, message, mac):
    try:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message.encode())
        h.verify(mac)
        return True
    except Exception:
        return False

# ---------------- APP ----------------
create_tables()

st.set_page_config(page_title="Secure P2P Authentication", layout="wide")

st.title("🔐 Secure Three-Phase P2P Authentication System")

menu = st.sidebar.selectbox(
    "Menu",
    [
        "Register Peer",
        "Phase 1: Identity Verification",
        "Phase 2: Session Key",
        "Phase 3: Secure Transfer",
        "Attack Simulation",
        "Authentication Logs"
    ]
)

if "session_key" not in st.session_state:
    st.session_state.session_key = None

# ---------------- REGISTER ----------------
if menu == "Register Peer":
    st.header("Register Peer")

    peer_name = st.text_input("Peer Name")

    if st.button("Generate Keys and Register"):
        if peer_name.strip() == "":
            st.error("Please enter a peer name")
        else:
            private_key, public_key = generate_keys()
            add_peer(peer_name, public_key)
            add_log(peer_name, "Registration", "Success", "Peer registered with RSA public key")

            st.success("Peer registered successfully")

            st.download_button(
                "Download Private Key",
                private_key,
                file_name=f"{peer_name}_private_key.pem"
            )

            st.subheader("Public Key")
            st.text_area("Public Key", public_key, height=180)

            st.warning("Keep the private key secret. It is required for Phase 1 verification.")

# ---------------- PHASE 1 ----------------
elif menu == "Phase 1: Identity Verification":
    st.header("Phase 1: RSA Identity Verification")

    peer_name = st.text_input("Peer Name")
    private_key = st.text_area("Paste Private Key", height=200)
    message = "Authenticate Peer"

    if st.button("Verify Identity"):
        public_key = get_peer(peer_name)

        if not public_key:
            st.error("Peer not found. Register peer first.")
        elif not private_key:
            st.error("Please paste private key.")
        else:
            try:
                signature = sign_message(private_key, message)
                verified = verify_signature(public_key, message, signature)

                if verified:
                    add_log(peer_name, "Phase 1", "Success", "RSA signature verified")
                    st.success("Phase 1 successful: Peer identity verified")
                else:
                    add_log(peer_name, "Phase 1", "Failed", "RSA signature verification failed")
                    st.error("Verification failed")
            except Exception as e:
                add_log(peer_name, "Phase 1", "Failed", str(e))
                st.error("Invalid private key or verification error")

# ---------------- PHASE 2 ----------------
elif menu == "Phase 2: Session Key":
    st.header("Phase 2: Secure Session Key Establishment")

    peer_name = st.text_input("Peer Name")

    if st.button("Generate Session Key"):
        if not get_peer(peer_name):
            st.error("Peer not found. Register peer first.")
        else:
            st.session_state.session_key = generate_hmac_key()
            add_log(peer_name, "Phase 2", "Success", "Session key generated")

            st.success("Phase 2 successful: Session key generated")
            st.code(st.session_state.session_key.decode())

# ---------------- PHASE 3 ----------------
elif menu == "Phase 3: Secure Transfer":
    st.header("Phase 3: Encrypted Content Transfer")

    peer_name = st.text_input("Peer Name")
    message = st.text_area("Enter Content to Transfer")

    if st.button("Encrypt and Transfer"):
        if st.session_state.session_key is None:
            st.error("Generate session key first in Phase 2.")
        elif message.strip() == "":
            st.error("Enter content first.")
        else:
            encrypted = encrypt_message(st.session_state.session_key, message)
            decrypted = decrypt_message(st.session_state.session_key, encrypted)

            mac = generate_mac(st.session_state.session_key, message)
            integrity = verify_mac(st.session_state.session_key, message, mac)

            if integrity:
                add_log(peer_name, "Phase 3", "Success", "Content encrypted and integrity verified")
                st.success("Phase 3 successful: Secure transfer completed")

                st.subheader("Encrypted Content")
                st.code(encrypted)

                st.subheader("HMAC")
                st.code(mac.hex())

                st.subheader("Decrypted Content")
                st.write(decrypted)
            else:
                add_log(peer_name, "Phase 3", "Failed", "Integrity verification failed")
                st.error("Integrity verification failed")

# ---------------- ATTACK SIMULATION ----------------
elif menu == "Attack Simulation":
    st.header("Identity Theft / MITM Attack Simulation")

    target_peer = st.text_input("Target Peer Name")
    fake_private, fake_public = generate_keys()
    fake_message = "Authenticate Peer"

    if st.button("Simulate Attack"):
        real_public_key = get_peer(target_peer)

        if not real_public_key:
            st.error("Target peer not found.")
        else:
            fake_signature = sign_message(fake_private, fake_message)
            attack_result = verify_signature(real_public_key, fake_message, fake_signature)

            if attack_result:
                add_log("Attacker", "Attack Simulation", "Failed", "Fake identity accepted")
                st.error("Attack succeeded: System vulnerable")
            else:
                add_log("Attacker", "Attack Simulation", "Success", "Fake identity rejected")
                st.success("Attack blocked: Fake identity rejected")

# ---------------- LOGS ----------------
elif menu == "Authentication Logs":
    st.header("Authentication Logs")

    logs = get_logs()

    if logs.empty:
        st.info("No logs available yet.")
    else:
        st.dataframe(logs, use_container_width=True)
