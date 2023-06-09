import requests

r=requests.post("http://127.0.0.1:5554/request",json={
    "method":"GET",
    "end_point":"https://thanhnien.vn"
})

