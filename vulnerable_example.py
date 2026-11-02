"""INTENTIONALLY VULNERABLE demo code for the scanner.

DO NOT RUN THIS FILE. It exists only so the Secure Coding Assistant has
insecure patterns to detect. The assistant never executes submitted code.
"""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import requests
import yaml

API_KEY = "sk_live_51HxExampleNotARealKey"
DB_PASSWORD = "SuperSecret123!"


def calculate(expression):
    # Dangerous: evaluates attacker-controlled text as Python
    return eval(expression)


def ping(host):
    # Dangerous: shell command built from user input
    os.system("ping -n 1 " + host)
    return subprocess.run("nslookup " + host, shell=True, capture_output=True)


def find_user(conn, username):
    cursor = conn.cursor()
    # Dangerous: SQL assembled with an f-string
    cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")
    return cursor.fetchall()


def load_profile(raw_bytes, yaml_text):
    profile = pickle.loads(raw_bytes)  # unsafe deserialization
    settings = yaml.load(yaml_text)  # unsafe loader
    return profile, settings


def fingerprint(password):
    return hashlib.md5(password.encode()).hexdigest()  # weak hash


def fetch(url):
    return requests.get(url, verify=False, timeout=10)  # TLS checks disabled


def safe_cleanup(path):
    try:
        os.remove(path)
    except Exception:
        pass
