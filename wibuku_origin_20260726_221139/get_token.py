import json, sys
addr = sys.argv[1]
import urllib.request
req = urllib.request.Request("https://api.mail.tm/token", data=json.dumps({"address": addr, "password": "KobraTest123!"}).encode(), headers={"Content-Type": "application/json"})
r = urllib.request.urlopen(req, timeout=15)
data = json.loads(r.read())
print(data['token'])
