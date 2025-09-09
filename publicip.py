import requests

public_ip = requests.get("https://api64.ipify.org?format=json").json() ["ip"]

print("My Public IP:", public_ip)