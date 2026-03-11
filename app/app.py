#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import json
from datetime import datetime
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ctf-challenge-secret-key-2023')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
FLAG = os.environ.get('FLAG', 'GENTLE{ID0R_1n_Th3_AP1_P4r4m3t3r}')

# Modèles
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    notes = db.relationship('Note', backref='author', lazy=True)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_private = db.Column(db.Boolean, default=True)

# Fonction utilitaire pour masquer le flag
def sanitize_content(content, user_id, note_author_id):
    """
    Masque le flag dans le contenu selon les permissions.
    Le flag n'est visible QUE via l'API, jamais dans l'interface web.
    """
    if FLAG in content:
        # Remplacer le flag par un message indiquant qu'il est masqué
        replacement = '[INFORMATION SENSIBLE - ACCÈS RESTREINT]'
        if note_author_id == 1:  # Si c'est une note admin
            replacement = '[CONTENU CONFIDENTIEL ADMIN - VISIBLE UNIQUEMENT VIA API AUTORISÉE]'
        
        content = content.replace(FLAG, replacement)
    
    # Masquer également les faux flags dans l'interface
    fake_flags = [
        'FAKE{f4ke_fl4g_123}',
        'FAKE{0ld_p@ssw0rd}',
        'FAKE{exp1red_t0ken_456}'
    ]
    
    for fake_flag in fake_flags:
        if fake_flag in content:
            content = content.replace(fake_flag, '[ANCIENNE INFORMATION MASQUÉE]')
    
    return content

# Routes d'authentification
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('notes'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            return redirect(url_for('notes'))
        
        return render_template('login.html', error='Identifiants incorrects')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Routes principales avec contenu masqué
@app.route('/notes')
def notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Récupère seulement les notes de l'utilisateur connecté
    user_notes = Note.query.filter_by(user_id=session['user_id']).all()
    
    # Préparer les notes avec contenu masqué
    safe_notes = []
    for note in user_notes:
        safe_content = sanitize_content(note.content, session['user_id'], note.user_id)
        
        # Créer un aperçu tronqué
        preview = safe_content[:150] + '...' if len(safe_content) > 150 else safe_content
        
        safe_notes.append({
            'id': note.id,
            'title': note.title,
            'content': preview,
            'full_content': safe_content,
            'created_at': note.created_at,
            'is_private': note.is_private,
            'author': note.author
        })
    
    return render_template('notes.html', notes=safe_notes, username=session['username'])

@app.route('/note/<int:note_id>')
def view_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    note = Note.query.get(note_id)
    
    if not note:
        return render_template('note.html', error="Note introuvable")
    
    # Masquer le flag dans l'interface web
    safe_content = sanitize_content(note.content, session['user_id'], note.user_id)
    
    return render_template('note.html', 
                         note={
                             'id': note.id,
                             'title': note.title,
                             'content': safe_content,
                             'created_at': note.created_at,
                             'is_private': note.is_private,
                             'author': note.author
                         })

# API endpoints - VULNÉRABILITÉ IDOR ICI
@app.route('/api/note/<int:note_id>', methods=['GET'])
def api_get_note(note_id):
    """
    Endpoint API pour récupérer une note - VULNÉRABLE À L'IDOR
    Le flag est visible ICI mais pas dans l'interface web !
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Non authentifié'}), 401
    
    note = Note.query.get(note_id)
    
    if not note:
        return jsonify({'error': 'Note non trouvée'}), 404
    
    # VULNÉRABILITÉ CRITIQUE : Aucune vérification d'autorisation
    # L'utilisateur peut accéder à n'importe quelle note sans vérification du propriétaire
    note_data = {
        'id': note.id,
        'title': note.title,
        'content': note.content,  # CONTENU COMPLET avec flag visible
        'created_at': note.created_at.isoformat(),
        'author': note.author.username,
        'is_private': note.is_private,
        'is_admin_note': note.author.is_admin,
        'warning': '⚠️ Cet endpoint ne doit pas être exposé publiquement'
    }
    
    return jsonify(note_data)

# Endpoint admin (protégé)
@app.route('/api/admin/notes')
def admin_notes():
    """Endpoint réservé aux administrateurs"""
    if 'user_id' not in session:
        return jsonify({'error': 'Non authentifié'}), 401
    
    user = User.query.get(session['user_id'])
    
    if not user or not user.is_admin:
        return jsonify({'error': 'Accès refusé'}), 403
    
    # Retourne toutes les notes
    all_notes = []
    for note in Note.query.all():
        note_content = note.content
        
        # Même pour les admins, on montre le contenu complet
        # mais on pourrait ajouter un avertissement
        if FLAG in note_content:
            note_content = note_content.replace(FLAG, f"🔒 FLAG: {FLAG} (confidentiel)")
        
        all_notes.append({
            'id': note.id,
            'title': note.title,
            'content': note_content,
            'author': note.author.username,
            'is_admin_note': note.author.is_admin
        })
    
    return jsonify(all_notes)

# Debug endpoint (avec fausses informations)
@app.route('/debug')
def debug():
    """Page de debug avec des fausses pistes"""
    debug_info = {
        'total_notes': Note.query.count(),
        'total_users': User.query.count(),
        'note_ids': [n.id for n in Note.query.all()],
        'security_status': 'ACTIVE',
        'api_endpoints': {
            '/api/note/<id>': {
                'method': 'GET',
                'description': 'Récupère une note spécifique',
                'security': 'Vérification des permissions activée'
            },
            '/api/admin/notes': {
                'method': 'GET', 
                'description': 'Récupère toutes les notes (admin seulement)',
                'security': 'Authentification admin requise'
            }
        },
        'warning': 'Certaines notes contiennent des informations sensibles protégées'
    }
    return jsonify(debug_info)

# Fonction d'initialisation de la base de données
def init_database():
    """Initialise la base de données avec le flag dans la note 6"""
    with app.app_context():
        print("🔄 Initialisation de la base de données...")
        
        # Vérifier si déjà initialisé
        if Note.query.first() is not None:
            print("⚠️  Base déjà initialisée, vérification...")
            note_6 = Note.query.get(6)
            if note_6 and FLAG in note_6.content:
                print("✅ Note 6 contient déjà le flag")
                return True
            else:
                print("❌ Note 6 ne contient pas le flag, réinitialisation...")
                db.drop_all()
                db.create_all()
        else:
            print("📦 Création des tables...")
            db.create_all()
        
        print(f"\n🎯 CONFIGURATION DU FLAG: {FLAG}")
        
        # 1. Créer les utilisateurs
        users_data = [
            ('admin', 'MdpComplexe9487!*/', True),
            ('john', 'password123', False),
            ('alice', 'alice2023', False),
        ]
        
        users = {}
        for username, password, is_admin in users_data:
            user = User(
                username=username,
                password_hash=generate_password_hash(password),
                is_admin=is_admin
            )
            db.session.add(user)
            users[username] = user
        
        db.session.commit()  # Pour avoir les IDs
        
        print("✅ Utilisateurs créés")
        
        # 2. Créer les notes - NOTE 6 contient le flag
        notes_to_create = []
        
        # Notes de l'admin (1-10)
        admin = users['admin']
        
        # Notes 1-5 : normales
        for i in range(1, 6):
            notes_to_create.append(Note(
                id=i,
                title=f"Note Administrative {i}",
                content=f"""Contenu de la note admin #{i}.

Ceci est une note standard contenant des informations administratives
pour le bon fonctionnement de l'entreprise.

Statut: Interne
Classification: Niveau 1""",
                user_id=admin.id,
                is_private=True
            ))
        
        # NOTE 6 - AVEC LE FLAG (mais masqué dans l'interface)
        notes_to_create.append(Note(
            id=6,
            title="CONFIDENTIEL - Réunion Conseil d'Administration",
            content=f"""PROTOCOLE DE SÉCURITÉ - NIVEAU MAXIMUM

RÉUNION DU CONSEIL D'ADMINISTRATION
Date: 15 novembre 2023 | Heure: 14:00-16:00

ORDRE DU JOUR:
1. Revue des incidents de sécurité
2. Nouveaux protocoles d'authentification
3. Audit des systèmes sensibles

DÉCISIONS PRINCIPALES:
- Implémentation de l'authentification à 2 facteurs
- Rotation mensuelle des clés d'API
- Audit hebdomadaire des logs d'accès

INFORMATIONS SENSIBLES:
• Serveur de sauvegarde: backup-01.entreprise.local
• Adresse IP réservée: 10.0.100.5
• Clé API principale: AKIAIOSFODNN7EXAMPLE
• Code d'accès temporaire: {FLAG}
• Contact urgence: security-team@entreprise.com

CONSIGNES DE SÉCURITÉ:
- Cette note ne doit pas être imprimée
- Ne pas discuter du contenu en public
- Destruction après lecture recommandée

CLASSIFICATION: NIVEAU 3 - TRÈS CONFIDENTIEL
DESTINATAIRES: Membres du CA uniquement""",
            user_id=admin.id,
            is_private=True
        ))
        
        # Notes 7-10 : normales
        for i in range(7, 11):
            notes_to_create.append(Note(
                id=i,
                title=f"Document Technique {i-6}",
                content=f"""Documentation technique #{i-6}.

Spécifications système et procédures opérationnelles.
Ces documents sont internes à l'équipe technique.

Version: 2.{i-6}
Statut: En révision""",
                user_id=admin.id,
                is_private=True
            ))
        
        # Notes pour les autres utilisateurs (11-20)
        other_users_notes = [
            (users['john'].id, "Projet Alpha - Planification", 
             "Étapes principales du projet Alpha..."),
            (users['john'].id, "Notes de réunion client", 
             "Client très satisfait de la démo..."),
            (users['alice'].id, "Liste de courses hebdomadaire", 
             "Lait, Œufs, Pain, Fruits, Légumes..."),
            (users['alice'].id, "Idées cadeaux Noël", 
             "Pour Marc: livre, pour Sophie: parfum..."),
            (users['john'].id, "Budget projet 2024", 
             "Répartition: Dev 60%, Design 20%, Tests 20%..."),
            (users['alice'].id, "Planning vacances", 
             "Noël: 24-26 déc, Nouvel An: 31 déc-2 janv...")
        ]
        
        next_id = 11
        for user_id, title, content in other_users_notes:
            notes_to_create.append(Note(
                id=next_id,
                title=title,
                content=content,
                user_id=user_id,
                is_private=True if next_id % 2 == 1 else False
            ))
            next_id += 1
        
        # Ajouter toutes les notes
        for note in notes_to_create:
            db.session.add(note)
        
        db.session.commit()
        
        # 3. Ajouter des fausses notes avec de faux flags pour brouiller
        fake_flag_notes = [
            (3, "FAKE{f4ke_fl4g_123}"),
            (8, "FAKE{0ld_p@ssw0rd}"),
            (12, "FAKE{exp1red_t0ken_456}")
        ]
        
        for note_id, fake_flag in fake_flag_notes:
            note = Note.query.get(note_id)
            if note:
                note.content += f"\n\n[DEBUG] Ancien code: {fake_flag} (invalide)"
                db.session.add(note)
        
        db.session.commit()
        
        # VÉRIFICATION FINALE
        total_notes = Note.query.count()
        note_6 = Note.query.get(6)
        
        print(f"\n📊 {total_notes} notes créées")
        
        if note_6 and FLAG in note_6.content:
            print(f"✅ SUCCÈS: Flag configuré dans la note 6!")
            print(f"   Titre: {note_6.title}")
            print(f"   Auteur: {note_6.author.username}")
            
            # Vérifier que le flag est masqué dans l'interface
            masked_content = sanitize_content(note_6.content, 2, note_6.user_id)
            if FLAG not in masked_content:
                print(f"✅ Le flag est bien masqué dans l'interface web")
            else:
                print(f"❌ ERREUR: Le flag n'est pas masqué!")
        else:
            print(f"❌ ERREUR: Flag NON trouvé dans note 6!")
            if note_6:
                print(f"   Contenu note 6: {note_6.content[:100]}...")
        
        return True

# Fonction de vérification
def verify_challenge():
    """Vérifie que le challenge est correctement configuré"""
    with app.app_context():
        print("\n🔍 VÉRIFICATION DU CHALLENGE")
        print("="*50)
        
        # 1. Vérifier la note 6
        note_6 = Note.query.get(6)
        if not note_6:
            print("❌ Note 6 n'existe pas!")
            return False
        
        print(f"📝 Note 6: {note_6.title}")
        print(f"   Auteur: {note_6.author.username}")
        
        # 2. Vérifier que le flag est présent dans la base
        if FLAG in note_6.content:
            print(f"✅ Flag présent dans la base de données")
        else:
            print(f"❌ Flag absent de la base!")
            return False
        
        # 3. Vérifier que le flag est masqué dans l'interface
        masked = sanitize_content(note_6.content, 2, note_6.user_id)
        if FLAG not in masked:
            print(f"✅ Flag correctement masqué dans l'interface")
        else:
            print(f"❌ Flag non masqué dans l'interface!")
            return False
        
        # 4. Vérifier l'accès API
        print(f"\n🌐 Test d'accès API:")
        try:
            from flask.testing import FlaskClient
            import json as json_module
            
            with app.test_client() as client:
                # Simuler une connexion
                client.post('/login', data={
                    'username': 'john',
                    'password': 'password123'
                })
                
                # Tester l'API
                response = client.get('/api/note/6')
                if response.status_code == 200:
                    data = json_module.loads(response.data)
                    if FLAG in data['content']:
                        print(f"✅ API retourne le flag (vulnérabilité active)")
                    else:
                        print(f"❌ API ne retourne pas le flag")
                        return False
                else:
                    print(f"❌ Erreur API: {response.status_code}")
                    return False
        except Exception as e:
            print(f"❌ Erreur lors du test API: {e}")
            return False
        
        print("="*50)
        print("🎉 Challenge correctement configuré!")
        return True

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 CHALLENGE - SECURENOTES PRO")
    print("="*60)
    
    # Créer le contexte d'application
    with app.app_context():
        # FORCER LA RÉINITIALISATION COMPLÈTE
        print("🔄 RÉINITIALISATION FORCÉE DE LA BASE DE DONNÉES...")
        
        # Supprimer toutes les tables existantes
        db.drop_all()
        print("   ✓ Anciennes tables supprimées")
        
        # Créer les nouvelles tables
        db.create_all()
        print("   ✓ Nouvelles tables créées")
        
        # Initialiser avec les données
        print("   ✓ Initialisation des données...")
        init_database()
        
        # Vérification
        verify_challenge()
    
    print(f"\n📌 ACCÈS AU CHALLENGE")
    print(f"   URL: http://0.0.0.0:8081")
    print(f"\n👥 COMPTES DE TEST:")
    print(f"   • john:password123")
    print(f"   • alice:alice2023")
    print(f"\n🎯 OBJECTIF:")
    print(f"   Trouver le flag dans la note 6")
    print(f"   Le flag n'est visible QUE via l'API /api/note/6")
    print(f"   Il est masqué dans l'interface web")
    print(f"\n💡 INDICE:")
    print(f"   L'API /api/note/<id> pourrait avoir une faille...")
    print(f"\n⚠️  FAUSSES PISTES:")
    print(f"   Des faux flags sont présents dans les notes 3, 8, 12")
    print(f"   Les messages de sécurité dans l'interface sont trompeurs")
    print("="*60 + "\n")
    
    # Démarrer le serveur
    app.run(host='0.0.0.0', port=8081, debug=False)
