import streamlit as st
import sqlite3
import requests
import hashlib
import concurrent.futures
from datetime import datetime
from urllib.parse import urlparse

# --- CONFIGURATION ---
DB_NAME = "lethal_scanner.db"
MAX_THREADS = 10  # Restored high-performance multi-threading configuration

# --- DATABASE ENGINE SETUP ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'User'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            target_url TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            status TEXT NOT NULL,
            is_deep INT DEFAULT 0,
            threads INT DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            path TEXT NOT NULL,
            http_status INTEGER NOT NULL,
            severity TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
        )
    ''')
    conn.commit()
    conn.close()

# --- SECURITY UTILITIES ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, email, password, role="User"):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
            (username, email, hash_password(password), role)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def login_user(username, password):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id, username, role FROM users WHERE username = ? AND password = ?",
        (username, hash_password(password))
    )
    user = cursor.fetchone()
    conn.close()
    return user 

# --- SINGLE PATH CHECK ENGINE ---
def check_individual_path(base_url, path, scan_id):
    full_url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        headers = {"User-Agent": "LethalScanner/2.0"}
        response = requests.get(full_url, headers=headers, timeout=5, allow_redirects=False)
        status = response.status_code
        
        # Validates response signals (200, 403, 301, 302 redirects)
        if status in [200, 403, 301, 302]:
            if status == 200:
                severity = "High Risk" if any(ext in path for ext in ['.env', 'config', 'sql', 'zip', '.php']) else "Medium"
            elif status == 403:
                severity = "Medium (Protected)"
            else:
                severity = "Low (Redirect)"
            
            # Persist findings to database instantly thread-safely
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO findings (scan_id, path, http_status, severity) VALUES (?, ?, ?, ?)",
                (scan_id, path, status, severity)
            )
            conn.commit()
            conn.close()
            return {"path": path, "status": status, "severity": severity}
    except requests.RequestException:
        pass
    return None

# --- RESTORED: CORE THREADED SCANNING ENGINE WITH DEEP SCAN RECURSION ---
def run_vulnerability_scan(target_url, wordlist, user_id, is_deep_scan, thread_count):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    cursor.execute(
        "INSERT INTO scans (user_id, target_url, scan_date, status, is_deep, threads) VALUES (?, ?, ?, ?, ?, ?)",
        (user_id, target_url, scan_date, "Running", 1 if is_deep_scan else 0, thread_count)
    )
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    st.info(f"🚀 Initializing Threaded Scan on: {target_url} utilizing {thread_count} worker threads...")
    
    default_paths = ["admin", "login.php", "images", "secure", "config.php", "vulnerable", "db", ".env", "backup.zip"]
    paths_to_scan = wordlist if wordlist else default_paths
    
    discovered_findings = []
    
    # Executing Multi-threaded pooling pool loops
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(check_individual_path, target_url, path, scan_id): path for path in paths_to_scan}
        
        progress_bar = st.progress(0)
        for idx, future in enumerate(concurrent.futures.as_completed(futures)):
            result = future.result()
            if result:
                discovered_findings.append(result)
                st.write(f"🔍 **Found:** `/{result['path']}` — Status Code: **{result['status']}** ({result['severity']})")
            progress_bar.progress((idx + 1) / len(paths_to_scan))

    # --- RESTORED: DEEP SCAN LOGIC (Recursive sub-directory spidering) ---
    if is_deep_scan and discovered_findings:
        st.warning("🕵️ Deep Scan Enabled: Mapping discovered paths for sub-directory escalation...")
        deep_paths = []
        
        # Pull paths that returned status 200/301/302 directories to recursively crawl deeper
        for item in discovered_findings:
            if item["status"] in [200, 301, 302] and "." not in item["path"]:
                for sub_path in default_paths:
                    deep_paths.append(f"{item['path']}/{sub_path}")
        
        if deep_paths:
            st.info(f"Spidertracking {len(deep_paths)} nested sub-directories...")
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as deep_executor:
                deep_futures = {deep_executor.submit(check_individual_path, target_url, dp, scan_id): dp for dp in deep_paths}
                for deep_future in concurrent.futures.as_completed(deep_futures):
                    deep_result = deep_future.result()
                    if deep_result:
                        st.write(f"💥 **Deep Found:** `/{deep_result['path']}` — Status: **{deep_result['status']}**")

    # Close and mark complete
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("UPDATE scans SET status = 'Completed' WHERE scan_id = ?", (scan_id,))
    conn.commit()
    conn.close()
    st.success("Scan processing sequence completed successfully!")

# --- WEB UI ENTRY POINT ---
st.set_page_config(page_title="LethalScanner", page_icon="🛡️")
init_db()

st.title("🛡️ LethalScanner System")
st.caption("Automated Web Directory Reconnaissance & Information Disclosure Scanner")

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.username = ""
    st.session_state.role = "User"

if not st.session_state.logged_in:
    auth_mode = st.sidebar.radio("Sign In / Sign Up", ["Login", "Register"])
    
    if auth_mode == "Login":
        st.subheader("Secure User Authentication")
        username = st.text_input("Username", key="login_user_input")
        password = st.text_input("Password", type="password", key="login_pass_input")
        if st.button("Sign In"):
            user = login_user(username, password)
            if user:
                st.session_state.logged_in = True
                st.session_state.user_id = user[0]
                st.session_state.username = user[1]
                st.session_state.role = user[2]
                st.success(f"Welcome back, {st.session_state.username}!")
                st.rerun()
            else:
                st.error("Invalid username or password.")
                
    elif auth_mode == "Register":
        st.subheader("Create a New Account")
        new_username = st.text_input("Username", key="reg_user_input")
        new_email = st.text_input("Email Address", key="reg_email_input")
        new_password = st.text_input("Password", type="password", key="reg_pass_input")
        
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'Admin'")
        row = cursor.fetchone()
        admin_count = row[0] if row else 0
        conn.close()
        
        if admin_count > 0:
            available_roles = ["User"]
            st.info("ℹ️ System administration configured. Additional registrations are standard access.")
        else:
            available_roles = ["User", "Admin"]
            st.warning("⚠️ No admin account found. The first account can be created as 'Admin'.")
        
        role_selection = st.selectbox("Account Type", available_roles, key="reg_role_input")
        
        if st.button("Sign Up"):
            if new_username and new_email and new_password:
                if register_user(new_username, new_email, new_password, role_selection):
                    st.success("✨ Account created! Switch the sidebar choice to 'Login' to sign in.")
                    st.rerun()
                else:
                    st.error("Username already exists.")
            else:
                st.warning("Please fill in all fields.")

else:
    # --- INSIDE PRIVILEGED ENVIRONMENT ---
    st.sidebar.markdown(f"**Logged in as:** {st.session_state.username} (`{st.session_state.role}`)")
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.session_state.username = ""
        st.session_state.role = "User"
        st.rerun()
    menu = ["Run Scanner", "Vulnerability History"]
    if st.session_state.role == "Admin":
        menu.append("Manage Wordlists (Admin Only)")
        
    choice = st.sidebar.selectbox("Navigation Menu", menu)

    # 1. RUN SCANNER INTERFACE (WITH THREADS AND DEEP SCAN CONFIGURATIONS)
    if choice == "Run Scanner":
        st.header("Configure Web Scan")
        target_url = st.text_input("Target URL", value="http://vulnweb.com")
        
        # --- RESTORED ORIGINAL INPUT CONFIGURATIONS ---
        col1, col2 = st.columns(2)
        with col1:
            thread_selection = st.slider("Execution Threads", min_value=1, max_value=MAX_THREADS, value=4, help="Higher threads mean a faster scan but higher resource consumption.")
        with col2:
            deep_scan_enabled = st.checkbox("Enable Deep Scan", value=False, help="Recursively crawls sub-directories found during scanning.")
            
        custom_wordlist_input = st.text_area("Custom Wordlist Paths (One entry per line - Optional)", placeholder="admin\nlogin.php\nimages")
        
        if st.button("Launch Lethal Scanner"):
            if target_url:
                if not (target_url.startswith("http://") or target_url.startswith("https://")):
                    st.error("Please include http:// or https:// protocol identifier in the target URL.")
                else:
                    wordlist = [line.strip() for line in custom_wordlist_input.split("\n") if line.strip()] if custom_wordlist_input else None
                    # Run the restored advanced threaded scan engine
                    run_vulnerability_scan(target_url, wordlist, st.session_state.user_id, deep_scan_enabled, thread_selection)
            else:
                st.warning("Target URL field cannot be empty.")

    # 2. VULNERABILITY HISTORY ARCHIVE LOGS
    elif choice == "Vulnerability History":
        st.header("Structured Reports Engine")
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        
        if st.session_state.role == "Admin":
            cursor.execute("SELECT scans.scan_id, users.username, scans.target_url, scans.scan_date, scans.status, scans.is_deep, scans.threads FROM scans JOIN users ON scans.user_id = users.user_id")
        else:
            cursor.execute("SELECT scan_id, 'Me', target_url, scan_date, status, is_deep, threads FROM scans WHERE user_id = ?", (st.session_state.user_id,))
            
        scans_data = cursor.fetchall()
        conn.close()
        
        if scans_data:
            for scan in scans_data:
                deep_label = "Deep" if scan[5] == 1 else "Quick"
                with st.expander(f"🌐 {scan[2]} [{deep_label} | {scan[6]}T] | Operator: {scan[1]} | Date: {scan[3]}"):
                    st.write(f"**Scan Session Status:** {scan[4]}")
                    
                    conn = sqlite3.connect(DB_NAME)
                    cursor = conn.cursor()
                    cursor.execute("SELECT path, http_status, severity FROM findings WHERE scan_id = ?", (scan[0],))
                    findings = cursor.fetchall()
                    conn.close()
                    
                    if findings:
                        for f in findings:
                            st.markdown(f"- `/{f[0]}` -> HTTP Status **{f[1]}** | Severity: **{f[2]}**")
                    else:
                        st.info("No vulnerable directories or paths detected for this session.")
        else:
            st.info("No historical scan parameters found in database records.")

    # 3. PRIVILEGED RULE CONFIGURATION ENGINE
    elif choice == "Manage Wordlists (Admin Only)":
        st.header("Admin Rule Engine")
        st.info("Welcome to the Admin workspace. You have access to configure system-wide parameters.")
        st.success("Access Granted.")

