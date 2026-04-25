 import streamlit as st
import sqlite3
import pandas as pd
import time
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.fernet import Fernet

DB_NAME = "p2p_auth.db"

st.set_page_config(
    page_title="Secure P2P Authentication",
    page_icon="🔐",
    layout="wide"
)

# ---------------- CSS ----------------
st.markdown("""
<style>
.main-title {
    font-size: 42px;
    font-weight: 800;
}
.subtitle {
    font-size: 18px;
    color: #666;
}
.metric-card {
    padding: 20px;
    border-radius: 15px;
    background: #f7f9fc;
    border: 1px solid #e6e9ef;
}
.success-box {
    padding: 15px;
    border-radius: 10px;
    background: #e8f7ee;
    color: #117a37;
    font-weight: 600;
}
.danger-box {
    padding: 15px;
    border-radius: 10px;
    background: #fdeaea;
    color: #a61b1b;
    font-weight: 600;
}
</style>
""", unsafe_allow_html=True)

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

def get_all_peers():
    conn = get_connection()
    df = pd.read_sql_query("SELECT id, peer_name, created_at FROM peers ORDER BY id DESC", conn)
    conn.close()
    return df

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

def clear_logs():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM logs")
    conn.commit()
    conn.close()

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
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def verify_signature(public_pem, message, signature):
    public_key = serialization.load_pem_public_key(public_pem.encode())
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def generate_session_key():
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

# ---------------- INITIALIZATION ----------------
create_tables()

if "session_key" not in st.session_state:
    st.session_state.session_key = None

if "verified_peer" not in st.session_state:
    st.session_state.verified_peer = None

# ---------------- SIDEBAR ----------------
st.sidebar.title("🔐 P2P Security")
menu = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Register Peer",
        "Phase 1: Identity Verification",
        "Phase 2: Session Key",
        "Phase 3: Secure Transfer",
        "Attack Simulation",
        "Authentication Logs",
        "About Project"
    ]
)

st.sidebar.markdown("---")
st.sidebar.info("MSc Project Prototype\n\nPython + Streamlit + SQLite + Cryptography")

# ---------------- HEADER ----------------
st.markdown('<div class="main-title">🔐 Secure Three-Phase P2P Authentication System</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Cryptography-driven authentication prototype for peer-to-peer content distribution systems.</div>', unsafe_allow_html=True)
st.markdown("---")

# ---------------- DASHBOARD ----------------
if menu == "Dashboard":
    st.header("System Dashboard")

    peers_df = get_all_peers()
    logs_df = get_logs()

    total_peers = len(peers_df)
    total_logs = len(logs_df)
    success_count = len(logs_df[logs_df["status"] == "Success"]) if not logs_df.empty else 0
    failed_count = len(logs_df[logs_df["status"] == "Failed"]) if not logs_df.empty else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Registered Peers", total_peers)
    c2.metric("Total Events", total_logs)
    c3.metric("Successful Events", success_count)
    c4.metric("Failed Events", failed_count)

    st.subheader("Protocol Flow")
    st.success("1. Register peer with RSA public key")
    st.success("2. Verify identity using RSA digital signature")
    st.success("3. Generate secure session key")
    st.success("4. Encrypt content and verify integrity using HMAC")
    st.success("5. Simulate identity theft / MITM attack")

    st.subheader("Registered Peers")
    if peers_df.empty:
        st.info("No peers registered yet.")
    else:
        st.dataframe(peers_df, use_container_width=True)

# ---------------- REGISTER ----------------
elif menu == "Register Peer":
    st.header("Register Peer")

    peer_name = st.text_input("Enter Peer Name", placeholder="Example: Peer_A")

    if st.button("Generate RSA Keys and Register", use_container_width=True):
        if peer_name.strip() == "":
            st.error("Please enter a peer name.")
        else:
            with st.spinner("Generating RSA key pair..."):
                time.sleep(1)
                private_key, public_key = generate_keys()
                add_peer(peer_name, public_key)
                add_log(peer_name, "Registration", "Success", "Peer registered with RSA public key")

            st.success("Peer registered successfully.")

            st.download_button(
                "⬇️ Download Private Key",
                private_key,
                file_name=f"{peer_name}_private_key.pem",
                mime="text/plain"
            )

            st.subheader("Public Key")
            st.text_area("Stored Public Key", public_key, height=180)

            st.warning("Keep the private key secret. It is required for Phase 1 verification.")

# ---------------- PHASE 1 ----------------
elif menu == "Phase 1: Identity Verification":
    st.header("Phase 1: RSA Identity Verification")

    peer_name = st.text_input("Peer Name", placeholder="Example: Peer_A")
    private_key = st.text_area("Paste Private Key", height=220)
    message = "Authenticate Peer"

    if st.button("Verify Identity", use_container_width=True):
        public_key = get_peer(peer_name)

        if not public_key:
            st.error("Peer not found. Register the peer first.")
        elif not private_key.strip():
            st.error("Please paste the private key.")
        else:
            try:
                start = time.time()
                signature = sign_message(private_key, message)
                verified = verify_signature(public_key, message, signature)
                end = time.time()
                latency = round((end - start) * 1000, 2)

                if verified:
                    st.session_state.verified_peer = peer_name
                    add_log(peer_name, "Phase 1", "Success", f"RSA signature verified in {latency} ms")
                    st.success(f"Phase 1 successful: Peer identity verified. Latency: {latency} ms")
                else:
                    add_log(peer_name, "Phase 1", "Failed", "RSA signature verification failed")
                    st.error("Verification failed.")
            except Exception as e:
                add_log(peer_name, "Phase 1", "Failed", str(e))
                st.error("Invalid private key or verification error.")

# ---------------- PHASE 2 ----------------
elif menu == "Phase 2: Session Key":
    st.header("Phase 2: Secure Session Key Establishment")

    peer_name = st.text_input("Peer Name", placeholder="Example: Peer_A")

    if st.button("Generate Session Key", use_container_width=True):
        if not get_peer(peer_name):
            st.error("Peer not found. Register the peer first.")
        elif st.session_state.verified_peer != peer_name:
            st.warning("Recommended: complete Phase 1 verification before generating session key.")
            st.session_state.session_key = generate_session_key()
            add_log(peer_name, "Phase 2", "Success", "Session key generated without prior verification warning")
            st.success("Session key generated.")
            st.code(st.session_state.session_key.decode())
        else:
            st.session_state.session_key = generate_session_key()
            add_log(peer_name, "Phase 2", "Success", "Secure session key generated")
            st.success("Phase 2 successful: Secure session key generated.")
            st.code(st.session_state.session_key.decode())

# ---------------- PHASE 3 ----------------
elif menu == "Phase 3: Secure Transfer":
    st.header("Phase 3: Encrypted Content Transfer")

    peer_name = st.text_input("Peer Name", placeholder="Example: Peer_A")
    message = st.text_area("Enter Content to Transfer", placeholder="Type confidential content here...")

    if st.button("Encrypt and Transfer", use_container_width=True):
        if st.session_state.session_key is None:
            st.error("Generate a session key first in Phase 2.")
        elif message.strip() == "":
            st.error("Please enter content.")
        else:
            start = time.time()
            encrypted = encrypt_message(st.session_state.session_key, message)
            decrypted = decrypt_message(st.session_state.session_key, encrypted)
            mac = generate_mac(st.session_state.session_key, message)
            integrity = verify_mac(st.session_state.session_key, message, mac)
            end = time.time()
            latency = round((end - start) * 1000, 2)

            if integrity and decrypted == message:
                add_log(peer_name, "Phase 3", "Success", f"Content encrypted and integrity verified in {latency} ms")
                st.success(f"Phase 3 successful: Secure transfer completed. Latency: {latency} ms")

                st.subheader("Encrypted Content")
                st.code(encrypted.decode())

                st.subheader("HMAC Integrity Code")
                st.code(mac.hex())

                st.subheader("Decrypted Content")
                st.info(decrypted)
            else:
                add_log(peer_name, "Phase 3", "Failed", "Integrity verification failed")
                st.error("Integrity verification failed.")

# ---------------- ATTACK SIMULATION ----------------
elif menu == "Attack Simulation":
    st.header("Identity Theft / MITM Attack Simulation")

    target_peer = st.text_input("Target Peer Name", placeholder="Example: Peer_A")

    st.write("This test creates a fake attacker key and tries to authenticate as the target peer.")

    if st.button("Simulate Attack", use_container_width=True):
        real_public_key = get_peer(target_peer)

        if not real_public_key:
            st.error("Target peer not found.")
        else:
            fake_private, _ = generate_keys()
            fake_message = "Authenticate Peer"
            fake_signature = sign_message(fake_private, fake_message)

            start = time.time()
            attack_result = verify_signature(real_public_key, fake_message, fake_signature)
            end = time.time()
            latency = round((end - start) * 1000, 2)

            if attack_result:
                add_log("Attacker", "Attack Simulation", "Failed", "Fake identity accepted")
                st.error("Attack succeeded: System is vulnerable.")
            else:
                add_log("Attacker", "Attack Simulation", "Success", f"Fake identity rejected in {latency} ms")
                st.success(f"Attack blocked: Fake identity rejected. Detection time: {latency} ms")

# ---------------- LOGS ----------------
elif menu == "Authentication Logs":
    st.header("Authentication Logs")

    logs = get_logs()

    if logs.empty:
        st.info("No logs available yet.")
    else:
        c1, c2 = st.columns(2)

        with c1:
            phase_filter = st.selectbox("Filter by Phase", ["All"] + sorted(logs["phase"].unique().tolist()))

        with c2:
            status_filter = st.selectbox("Filter by Status", ["All"] + sorted(logs["status"].unique().tolist()))

        filtered = logs.copy()

        if phase_filter != "All":
            filtered = filtered[filtered["phase"] == phase_filter]

        if status_filter != "All":
            filtered = filtered[filtered["status"] == status_filter]

        st.dataframe(filtered.drop(columns=["id"]), use_container_width=True)

        st.download_button(
            "⬇️ Download Logs as CSV",
            filtered.to_csv(index=False),
            file_name="authentication_logs.csv",
            mime="text/csv"
        )

        if st.button("Clear Logs"):
            clear_logs()
            st.warning("Logs cleared. Refresh the page to update.")

# ---------------- ABOUT ----------------
elif menu == "About Project":
    st.header("About This Project")

    st.write("""
    This prototype implements a secure three-phase cryptography-driven authentication technique
    for peer-to-peer content distribution systems.
    """)

    st.subheader("Three Phases")
    st.markdown("""
    1. **Phase 1: Identity Verification**  
       RSA digital signatures are used to verify peer identity.

    2. **Phase 2: Session Key Establishment**  
       A secure symmetric session key is generated for encrypted communication.

    3. **Phase 3: Secure Content Transfer**  
       Content is encrypted and verified using HMAC integrity checking.
    """)

    st.subheader("Security Evaluation")
    st.write("""
    The system includes an attack simulation module to test resistance against identity theft
    and man-in-the-middle attacks. A fake attacker key is generated and tested against the stored
    legitimate public key. If the system rejects the fake signature, the attack is successfully blocked.
    """)

    st.subheader("Technology Stack")
    st.markdown("""
    - Python
    - Streamlit
    - SQLite
    - RSA Cryptography
    - Fernet Symmetric Encryption
    - HMAC Integrity Verification
    """)
