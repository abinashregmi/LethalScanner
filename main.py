import streamlit as st
import requests
import sqlite3
import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import os
import time

# --- DATABASE LAYER
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
                               status_code INTEGER, timestamp TEXT)''')
            conn.commit()

    def add_target(self, url):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("INSERT INTO targets (url, timestamp) VALUES (?, ?)", (url, ts))
            return cursor.lastrowid

    def log_result(self, target_id, path, status):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("INSERT INTO results (target_id, path, status_code, timestamp) VALUES (?, ?, ?, ?)",
                           (target_id, path, status, ts))

    def get_all_results(self):
        with sqlite3.connect(self.db_name) as conn:
            return pd.read_sql_query("""
                SELECT t.url as Target, r.path as Path, r.status_code as Status, r.timestamp as Discovered
                FROM results r JOIN targets t ON r.target_id = t.id
                ORDER BY r.id DESC
            """, conn)

# --- WEB APP INTERFACE ---
st.set_page_config(page_title="LethalScanner Dashboard", layout="wide")
db = DatabaseHandler()

st.title("🛡️ LethalScanner")
st.markdown("### Web Reconnaissance & Information Disclosure Tool")
st.info("BSc. CSIT 5th Semester Project - New Summit College")

# Sidebar for Configuration
st.sidebar.header("Scan Configuration")
target_url = st.sidebar.text_input("Target URL", placeholder="https://example.com")
threads = st.sidebar.slider("Thread Count", 5, 50, 20)
timeout = st.sidebar.number_input("Timeout (sec)", 1, 10, 3)

# Wordlist Selection
wordlist_option = st.sidebar.selectbox("Wordlist Source", ["Standard (Built-in)", "Upload Custom TXT"])
if wordlist_option == "Upload Custom TXT":
    uploaded_file = st.sidebar.file_uploader("Choose a file")
    if uploaded_file:
        paths = [line.decode("utf-8").strip() for line in uploaded_file]
    else:
        paths = []
else:
    # Academic Sample Wordlist
    paths = [".env", ".git/config", "admin/", "config.php", "wp-admin", "phpinfo.php", "server-status", ".htaccess", "backup.zip", "test.php"]

# Main Layout
col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("Control Panel")
    start_btn = st.button("🚀 Start Reconnaissance", use_container_width=True)
    
    if start_btn and target_url:
        if not target_url.startswith("http"):
            st.error("Please include http:// or https://")
        else:
            target_id = db.add_target(target_url)
            st.write(f"Initialized Scan ID: `{target_id}`")
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            found_count = 0
            
            def scan_task(path):
                full_url = f"{target_url.rstrip('/')}/{path.lstrip('/')}"
                try:
                    resp = requests.get(full_url, timeout=timeout, allow_redirects=False)
                    if resp.status_code in [200, 403, 401, 301]:
                        db.log_result(target_id, path, resp.status_code)
                        return (path, resp.status_code)
                except:
                    pass
                return None

            with ThreadPoolExecutor(max_workers=threads) as executor:
                results = []
                total = len(paths)
                for i, res in enumerate(executor.map(scan_task, paths)):
                    if res:
                        results.append(res)
                        found_count += 1
                    progress_bar.progress((i + 1) / total)
                    status_text.text(f"Scanning: {i+1}/{total} paths...")
            
            st.success(f"Scan Finished! Discovered {found_count} potential vulnerabilities.")
    elif start_btn:
        st.warning("Please enter a Target URL.")

with col2:
    st.subheader("Audit Logs (Database View)")
    df = db.get_all_results()
    if not df.empty:
        # Style findings (200 OK as success, 403 as warning)
        def color_status(val):
            color = 'green' if val == 200 else 'orange' if val == 403 else 'white'
            return f'color: {color}'
        
        st.dataframe(df.style.applymap(color_status, subset=['Status']), use_container_width=True)
        
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Export CSV Report", data=csv, file_name="audit_report.csv", mime="text/csv")
    else:
        st.write("No results in database yet.")

# Database Statistics
if not df.empty:
    st.divider()
    st.subheader("Quick Analytics")
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Discoveries", len(df))
    c2.metric("200 OK Files", len(df[df['Status'] == 200]))
    c3.metric("403 Forbidden", len(df[df['Status'] == 403]))