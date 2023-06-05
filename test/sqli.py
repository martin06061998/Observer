
import datetime
import time
import requests
from datetime import datetime

http_proxy = "http://127.0.0.1:8080"
https_proxy = "https://127.0.0.1:8080"

proxies = {
    'https': 'http://127.0.0.1:8080',
    'http': 'http://127.0.0.1:8080'
}       
headers = {'tag':"sqli"}
now = time.time()
for _ in range(20):
    r=requests.get("http://127.0.0.1:5555/api")
    print(r.status_code)
later = time.time()
difference = later - now
print(difference)