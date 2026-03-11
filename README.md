# Challenge CTF : Notes Internes - IDOR

## Description
Vous venez d'être embauché comme stagiaire dans une entreprise qui utilise une plateforme interne de notes. Votre manager vous a donné des identifiants pour accéder au système, mais vous soupçonnez que certaines notes confidentielles pourraient être mal protégées...

**Format du flag :** `GENTLE{...}`

## Installation et lancement

### Option 1 : Docker (recommandé)
```bash
# Cloner le dépôt
git clone <repo>
cd idor-challenge

# Lancer avec Docker Compose
docker-compose up --build

# Ou avec Docker directement
docker build -t idor-challenge .
docker run -p 8080:8080 -e FLAG=GENTLE{ID0R_1n_Th3_AP1_P4r4m3t3r} idor-challenge