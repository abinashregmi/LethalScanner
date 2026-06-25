# 🛡️ LethalScanner

A lightweight, automated web vulnerability scanner built in Python. This tool allows security enthusiasts and web administrators to scan target URLs for common security flaws, logging vulnerability reports to a local relational database for structured analysis.

🚀 **[View Live Demo](https://lethalscanner-d8gfrftu9znwkk69kgksoc.streamlit.app/)**

---

## ✨ Features

- **Automated URL Scanning:** Analyzes target web addresses for security vulnerabilities and misconfigurations.
- **Relational Data Logging:** Uses an optimized SQLite3 database backend to log scan history, target endpoints, and discovered vulnerabilities.
- **Interactive Web Interface:** Built with a clean, responsive Streamlit dashboard interface for real-time monitoring and reporting.
- **Lightweight & Portable:** No complex setup required; easy deployment via Streamlit Cloud.

---

## 🛠️ Tech Stack

- **Frontend & Dashboard:** Streamlit
- **Core Logic & Scripting:** Python 3
- **Database Engine:** SQLite3

---

## 📥 Installation & Local Setup

To run LethalScanner locally on your machine, follow these simple steps:

### 1. Clone the Repository
```bash
git clone https://github.com
cd LethalScanner
```

### 2. Install Dependencies
Make sure you have Python installed, then run:
```bash
pip install -r requirements.txt
```
*(Note: If you don't have a requirements.txt file yet, just install Streamlit using `pip install streamlit`)*

### 3. Run the Application
```bash
streamlit run app.py
```
*(Replace `main.py` with the actual name of your main Python file if it is different)*

---

## 📸 Dashboard Preview

| Scan Configuration | Vulnerability Reports |
|---|---|
<img width="1448" height="848" alt="image" src="https://github.com/user-attachments/assets/7d8b0894-ea85-435b-9903-c6733edfb726" />
<img width="909" height="661" alt="image" src="https://github.com/user-attachments/assets/84f9c0fe-b3a4-400f-b846-6a0eef9bd4d1" />


---

## 🧑‍💻 Author

- **Abinash Regmi**
- GitHub: [@abinashregmi](https://github.com)
- LinkedIn: [abinashregmi](https://linkedin.com)
- Portfolio: [regmiabinash72.com.np](https://regmiabinash72.com.np)

---

## ⚠️ Disclaimer

*This tool is developed strictly for educational and authorized security testing purposes. Do not use LethalScanner against any website or infrastructure without explicit written permission from the owner.*
