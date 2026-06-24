import urllib.request

resp = urllib.request.urlopen('http://127.0.0.1:8080/')
print(resp.getcode())
