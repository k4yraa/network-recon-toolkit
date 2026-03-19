import requests
import socket

def ip_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        data = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()

        print("\n[IP INFORMATION]")
        print(f"IP       : {ip}")
        print(f"Country  : {data.get('country')}")
        print(f"City     : {data.get('city')}")
        print(f"ISP      : {data.get('isp')}")
        print(f"Org      : {data.get('org')}")

    except Exception as e:
        print(f"[ERROR] IP lookup failed: {e}")


def http_info(url):
    try:
        res = requests.get(url, timeout=5)

        print("\n[HTTP INFORMATION]")
        print(f"Status   : {res.status_code}")
        print(f"Server   : {res.headers.get('Server')}")
        print(f"Content  : {res.headers.get('Content-Type')}")

    except Exception as e:
        print(f"[ERROR] HTTP request failed: {e}")


def main():
    target = input("Target (example.com): ").strip()

    if not target.startswith("http"):
        url = "http://" + target
    else:
        url = target

    print("\n--- Recon Started ---")

    ip_lookup(target)
    http_info(url)

    print("\n--- Done ---")


if __name__ == "__main__":
    main()
