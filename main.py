import requests
import socket

def ip_lookup(domain):
    ip = socket.gethostbyname(domain)
    data = requests.get(f"http://ip-api.com/json/{ip}").json()
    
    print("\n[IP INFO]")
    print("IP:", ip)
    print("Country:", data.get("country"))
    print("ISP:", data.get("isp"))

def http_info(url):
    res = requests.get(url)
    
    print("\n[HTTP INFO]")
    print("Status:", res.status_code)
    print("Server:", res.headers.get("Server"))

target = input("Target (example.com): ")

ip_lookup(target)
http_info(f"http://{target}")