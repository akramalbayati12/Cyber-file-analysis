import os
import re
import pandas as pd
import pytesseract
import fitz  # PyMuPDF
import torch
import multiprocessing
import mimetypes
import spacy
import pytz
import tldextract
from PIL import Image, ExifTags
from email_validator import validate_email, EmailNotValidError
import phonenumbers
from zxcvbn import zxcvbn
from datetime import datetime
from collections import Counter
import dateparser
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from threading import Thread
import queue

# ===================== NLP and Patterns ===================== #
nlp = spacy.load("en_core_web_sm")

SOCIAL_APPS = ["facebook", "instagram", "whatsapp", "telegram", "signal",
    "snapchat", "tiktok", "messenger", "viber", "threads"]

BROWSERS = ["chrome", "firefox", "edge", "opera", "brave",
    "safari", "vivaldi", "tor", "yandex", "uc browser"]

UTILITY_PROGRAMS = ["outlook", "thunderbird", "putty", "teamviewer", "nmap",
    "wireshark", "zoom", "skype", "discord", "vlc",
    "winrar", "7zip", "vmware", "virtualbox", "notepad++",
    "powershell", "cmd", "bash", "zsh", "python", "java", "php", "ftp", "ssh"]

KNOWN_PROGRAMS = SOCIAL_APPS + BROWSERS + UTILITY_PROGRAMS
KNOWN_DEVICES = ["laptop", "desktop", "android", "iphone", "windows", "macbook"]

# ===================== Extract Functions ===================== #
def extract_text_from_file(file_path):
    if file_path.endswith((".txt", ".log", ".json", ".html")):
        with open(file_path, "r", errors="ignore") as f:
            return f.read()
    elif file_path.endswith(".pdf"):
        text = ""
        doc = fitz.open(file_path)
        for page in doc:
            text += page.get_text()
        return text
    elif file_path.lower().endswith((".png", ".jpg", ".jpeg")):
        return pytesseract.image_to_string(Image.open(file_path))
    elif file_path.endswith(".csv") or file_path.endswith(".xlsx"):
        df = pd.read_csv(file_path) if file_path.endswith(".csv") else pd.read_excel(file_path)
        return df.to_string(index=False)
    return ""

def extract_pdf_metadata(file_path):
    try:
        doc = fitz.open(file_path)
        return {k: v for k, v in doc.metadata.items() if v}
    except:
        return {}

def extract_image_metadata(file_path):
    try:
        img = Image.open(file_path)
        info = img._getexif()
        return {ExifTags.TAGS.get(k, k): v for k, v in info.items()} if info else {}
    except:
        return {}

def extract_links(text):
    pattern = r"https?://[\w\-._~:/?#[\]@!$&'()*+,;=%]+"
    return list(set(re.findall(pattern, text)))

def extract_passwords(text):
    pattern = r"(?i)(password|pass|pwd)\s*[:=\-]?\s*([\w@#\-!$%^&*]+)"
    results = []
    for match in re.finditer(pattern, text):
        pw = match.group(2)
        result = zxcvbn(pw)
        context = text[max(0, match.start()-50):match.end()+50]
        results.append({"type": "Password", "value": pw, "extra": f"Strength: {result['score']}, Context: {context.strip()}"})
    return results

def extract_emails(text):
    pattern = r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
    matches = re.finditer(pattern, text)
    results = []
    for m in matches:
        email = m.group(0)
        try:
            validate_email(email)
            valid = True
        except EmailNotValidError:
            valid = False
        context = text[max(0, m.start()-40):m.end()+40]
        results.append({"type": "Email", "value": email, "extra": f"Valid: {valid}, Context: {context.strip()}"})
    return results

def extract_phones(text):
    results = []
    for match in phonenumbers.PhoneNumberMatcher(text, ""):
        phone = match.raw_string
        num = match.number
        valid = phonenumbers.is_valid_number(num)
        try:
            region = phonenumbers.region_code_for_number(num)
            kind = phonenumbers.number_type(num)
            country = phonenumbers.geocoder.description_for_number(num, "en")
        except:
            region = country = kind = "Unknown"
        results.append({"type": "Phone", "value": phone, "extra": f"Valid: {valid}, Region: {region}, Country: {country}, Type: {kind}"})
    return results

def extract_timestamps(text):
    return [dateparser.parse(w, settings={"RETURN_AS_TIMEZONE_AWARE": True}) for w in text.split() if dateparser.parse(w)]

def analyze_file(file_path):
    text = extract_text_from_file(file_path)
    results = []
    for item in extract_emails(text) + extract_phones(text) + extract_passwords(text):
        item["file"] = os.path.basename(file_path)
        results.append(item)
    for link in extract_links(text):
        results.append({"file": os.path.basename(file_path), "type": "Link", "value": link, "extra": ""})
    return results

# ===================== GUI ===================== #
def start_gui():
    def browse_folder():
        folder = filedialog.askdirectory()
        if folder:
            folder_var.set(folder)

    def start_analysis():
        folder = folder_var.get()
        if not folder:
            messagebox.showerror("Error", "Please select a folder.")
            return
        tree.delete(*tree.get_children())
        q = queue.Queue()

        def worker():
            files = [os.path.join(folder, f) for f in os.listdir(folder)]
            for f in files:
                for row in analyze_file(f):
                    q.put(row)
            q.put(None)

        def display():
            while True:
                res = q.get()
                if res is None:
                    break
                tree.insert("", "end", values=(res["file"], res["type"], res["value"], res["extra"]))

        Thread(target=worker).start()
        Thread(target=display).start()

    def save_results():
        with open("analysis_output.txt", "w", encoding="utf-8") as f:
            for row in tree.get_children():
                values = tree.item(row)['values']
                f.write("\t".join(str(v) for v in values) + "\n")
        messagebox.showinfo("Saved", "Results saved to analysis_output.txt")

    root = tk.Tk()
    root.title("Cyber Data Analyzer")
    root.geometry("1342x581")

    folder_var = tk.StringVar()

    tk.Label(root, text="Select Folder:").pack()
    tk.Entry(root, textvariable=folder_var, width=70).pack()
    tk.Button(root, text="Browse", command=browse_folder).pack()
    tk.Button(root, text="Start Analysis", command=start_analysis).pack()

    columns = ("File", "Type", "Value", "Details")
    tree = ttk.Treeview(root, columns=columns, show="headings")
    for col in columns:
        tree.heading(col, text=col)
        tree.column(col, width=300)
    tree.pack(expand=True, fill="both")

    tk.Button(root, text="Save to TXT", command=save_results).pack(pady=10)
    root.mainloop()

if __name__ == "__main__":
    start_gui()

