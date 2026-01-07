# Challenge CTF : Notes Internes - IDOR

## Description
Vous avez obtenu un accès à la plateforme de notes internes d'une entreprise. 
En tant qu'employé normal, vous ne devriez pouvoir voir que vos propres notes... 
mais peut-être que le système a une faille ?

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