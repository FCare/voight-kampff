#!/usr/bin/env python3
"""
Script de migration automatique pour ajouter les colonnes OAuth à Voight-Kampff
"""

import sqlite3
import os
import logging

def migrate_database():
    """Migre automatiquement la base de données pour ajouter le support OAuth"""
    
    db_path = os.getenv("VK_DB_PATH", "/data/voight-kampff.db")
    
    print(f"🔄 Vérification de la migration OAuth pour {db_path}...")
    
    if not os.path.exists(db_path):
        print(f"📁 Base de données {db_path} n'existe pas encore, elle sera créée avec le bon schéma")
        return True
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Vérifier si les colonnes OAuth existent déjà
        cursor.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]
        
        oauth_columns = ['google_id', 'auth_provider', 'profile_picture']
        missing_columns = [col for col in oauth_columns if col not in columns]
        
        if not missing_columns:
            print(f"✅ Migration OAuth déjà appliquée")
            conn.close()
            return True
        
        print(f"🔧 Migration OAuth nécessaire - colonnes manquantes: {missing_columns}")
        
        # Sauvegarde des données existantes
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        print(f"📊 Sauvegarde de {user_count} utilisateur(s) existant(s)")
        
        # Créer une table temporaire avec le nouveau schéma
        cursor.execute("""
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                hashed_password TEXT, -- Maintenant nullable pour OAuth
                is_active BOOLEAN DEFAULT FALSE,
                is_admin BOOLEAN DEFAULT FALSE,
                max_api_keys INTEGER DEFAULT 100,
                allowed_scopes TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                google_id TEXT UNIQUE,
                auth_provider TEXT DEFAULT 'local',
                profile_picture TEXT
            )
        """)
        
        # Copier toutes les données existantes
        cursor.execute("""
            INSERT INTO users_new (
                id, username, email, hashed_password, is_active, is_admin, 
                max_api_keys, allowed_scopes, created_at, last_login,
                auth_provider
            )
            SELECT 
                id, username, email, hashed_password, is_active, is_admin,
                max_api_keys, allowed_scopes, created_at, last_login,
                'local'
            FROM users
        """)
        
        # Remplacer l'ancienne table
        cursor.execute("DROP TABLE users")
        cursor.execute("ALTER TABLE users_new RENAME TO users")
        
        # Recréer les index
        cursor.execute("CREATE UNIQUE INDEX idx_users_username ON users(username)")
        cursor.execute("CREATE UNIQUE INDEX idx_users_email ON users(email)")
        cursor.execute("CREATE UNIQUE INDEX idx_users_google_id ON users(google_id)")
        
        # Vérifier le résultat
        cursor.execute("SELECT COUNT(*) FROM users WHERE auth_provider = 'local'")
        migrated_count = cursor.fetchone()[0]
        
        conn.commit()
        conn.close()
        
        print(f"✅ Migration OAuth réussie ! {migrated_count} utilisateur(s) migré(s)")
        return True
        
    except Exception as e:
        print(f"❌ Erreur lors de la migration: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return False

if __name__ == "__main__":
    migrate_database()