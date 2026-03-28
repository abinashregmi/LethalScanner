import streamlit as st
import requests
import sqlite3
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import os

# --- DATABASE LAYER ---
class DatabaseHandler:
    def __init__(self, db_name="lethal_scanner.db"):
        self.db_name = db_name
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS targets 
                              (id INTEGER PRIMARY KEY, url TEXT, timestamp TEXT)''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS results 
                              (id INTEGER PRIMARY KEY, target_id INTEGER, path TEXT, 
                               status_code INTEGER, details TEXT, timestamp TEXT)''')
            conn.commit()

    def add_target(self, url):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("INSERT INTO targets (url, timestamp) VALUES (?, ?)", (url, ts))
            conn.commit()
            return cursor.lastrowid

    def log_result(self, target_id, path, status, details="None"):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("INSERT INTO results (target_id, path, status_code, details, timestamp) VALUES (?, ?, ?, ?, ?)",
                           (target_id, path, status, details, ts))
            conn.commit()

    def get_all_results(self):
        with sqlite3.connect(self.db_name) as conn:
            return pd.read_sql_query("""
                SELECT t.url as Target, r.path as Path, r.status_code as Status, r.details as Details, r.timestamp as Discovered
                FROM results r JOIN targets t ON r.target_id = t.id
                ORDER BY r.id DESC
            """, conn)

# --- UI SETUP ---
st.set_page_config(page_title="LethalScanner Pro", layout="wide")
db = DatabaseHandler()

st.title("🛡️ LethalScanner")
st.markdown("### Full-Spectrum Web Vulnerability & Reconnaissance")

# Sidebar
st.sidebar.header("Scan Settings")
target_url = st.sidebar.text_input("Target URL", value="http://localhost:8000")
threads = st.sidebar.slider("Threads", 1, 50, 15)
timeout = st.sidebar.number_input("Timeout", 1, 10, 3)

# Expanded Wordlist
wordlist_input = st.sidebar.text_area("Wordlist (One per line)", 
    ".env\n.git/config\nadmin/\nconfig.php\nphpinfo.php\n.htaccess\n.ssh/id_rsa\nbackup.sql\nsetup.php\n/api/v1/users\n/console")
paths = [p.strip() for p in wordlist_input.split('\n') if p.strip()]

col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("Scanner Control")
    if st.button("🚀 Execute Deep Scan", use_container_width=True):
        if not target_url.startswith("http"):
            st.error("Invalid URL format.")
        else:
            target_id = db.add_target(target_url)
            progress = st.progress(0)
            status_msg = st.empty()
            found = 0

            def scan_task(path):
                url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
                try:
                    # We use a real User-Agent to bypass simple anti-bot filters
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) LethalScanner/1.1'}
                    resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=False)
                    
                    status = resp.status_code
                    detail = "Potential Info Leak"
                    
                    # Vulnerability Logic
                    # 200: Exposed file | 403: Forbidden but exists | 500: Server failure/Debug leak | 301: Redirect to sensitive area
                    if status in [200, 403, 401, 301, 302, 500]:
                        # Check for Technology Leakage in headers
                        tech = resp.headers.get('X-Powered-By', resp.headers.get('Server', 'Generic'))
                        detail = f"Tech: {tech}"
                        
                        db.log_result(target_id, path, status, detail)
                        return True
                except:
                    pass
                return False

            with ThreadPoolExecutor(max_workers=threads) as executor:
                for i, hit in enumerate(executor.map(scan_task, paths)):
                    if hit: found += 1
                    progress.progress((i + 1) / len(paths))
                    status_msg.text(f"Processing:")

            st.success(f"Scan Finished. {found} Vulnerabilities logged.")

with col2:
    st.subheader("Vulnerability Discovery Log")
    df = db.get_all_results()
    if not df.empty:
        def style_rows(row):
            if row.Status == 200: 
                return ['background-color: #1b4332; color: #d4edda'] * len(row) # Dark Green (Success)
            if row.Status == 500: 
                return ['background-color: #721c24; color: #f8d7da'] * len(row) # Dark Red (Danger)
            if row.Status == 403: 
                return ['background-color: #856404; color: #fff3cd'] * len(row) # Dark Gold/Ochre (Warning)
                return ['color: #ffffff'] * len(row) # Default White text

            return [''] * len(row)

        st.dataframe(df.style.apply(style_rows, axis=1), use_container_width=True)
    else:
        st.info("No vulnerabilities found in database.")