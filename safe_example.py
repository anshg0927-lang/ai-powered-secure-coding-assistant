"""Demo code that follows safer practices. The scanner should report nothing here
(which still does not prove the code is perfectly secure)."""
import ast
import hashlib
import logging
import os
import sqlite3
import subprocess

import requests
import yaml

API_KEY = os.environ.get("API_KEY", "")


def calculate(expression: str):
    # Only Python literals are accepted
    return ast.literal_eval(expression)


def list_directory(path: str) -> str:
    result = subprocess.run(["ls", "-l", path], capture_output=True, text=True, timeout=10, check=True)
    return result.stdout


def find_user(conn: sqlite3.Connection, username: str):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))
    return cursor.fetchall()


def load_settings(yaml_text: str):
    return yaml.safe_load(yaml_text)


def checksum(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str):
    return requests.get(url, timeout=10)


def cleanup(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        logging.exception("Could not remove %s", path)
