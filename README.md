# Voight-Kampff Authentication Service

Un service d'authentification par clés API autonome basé sur Flask et SQLite.

## Vue d'ensemble

Voight-Kampff est un service d'authentification léger qui fournit :
- Gestion des utilisateurs avec interface web
- Génération et validation de clés API
- Système d'authentification sécurisé
- Interface d'administration
- Base de données SQLite intégrée

## Installation et démarrage rapide

### Prérequis
- Docker
- Docker Compose

### Démarrage

1. **Cloner ou copier le répertoire voight-kampff**

2. **Configurer l'environnement**
   ```bash
   cd voight-kampff
   cp .env.example .env
   ```

3. **Générer une clé secrète sécurisée**
   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(64))"
   ```

4. **Éditer le fichier .env avec vos valeurs**
   - Remplacez `VK_SECRET_KEY` par la clé générée
   - Configurez les identifiants admin (`VK_ADMIN_USERNAME`, `VK_ADMIN_PASSWORD`, `VK_ADMIN_EMAIL`)

5. **Démarrer le service**
   ```bash
   docker-compose up -d
   ```

6. **Accéder au service**
   - Interface web : http://localhost:8080
   - Connexion avec les identifiants admin configurés

## Configuration

### Variables d'environnement

| Variable | Description | Défaut |
|----------|-------------|---------|
| `VK_ADMIN_USERNAME` | Nom d'utilisateur admin initial | - |
| `VK_ADMIN_PASSWORD` | Mot de passe admin initial | - |
| `VK_ADMIN_EMAIL` | Email admin initial | - |
| `VK_SECRET_KEY` | Clé secrète pour les sessions | - |
| `VK_SESSION_EXPIRE_HOURS` | Durée d'expiration des sessions | 24 |
| `VK_DB_PATH` | Chemin de la base de données | /data/voight-kampff.db |

### Volumes

- `./data:/data` - Stockage de la base de données SQLite
- `./config:/config` - Fichiers de configuration (optionnel)

## Utilisation

### Interface Web
1. Connectez-vous avec les identifiants admin
2. Créez des utilisateurs
3. Générez des clés API
4. Gérez les permissions

### API
Le service expose des endpoints pour :
- Validation des clés API
- Gestion des utilisateurs
- Authentification

## Maintenance

### Sauvegarde
```bash
# Sauvegarder la base de données
cp ./data/voight-kampff.db ./backups/voight-kampff-$(date +%Y%m%d).db
```

### Logs
```bash
# Voir les logs
docker-compose logs voight-kampff

# Suivre les logs en temps réel
docker-compose logs -f voight-kampff
```

### Mise à jour
```bash
# Arrêter le service
docker-compose down

# Reconstruire l'image
docker-compose build

# Redémarrer
docker-compose up -d
```

## Sécurité

- Utilisez des mots de passe forts pour les comptes admin
- Générez une clé secrète unique pour chaque installation
- Sauvegardez régulièrement la base de données
- Surveillez les logs d'accès
- Utilisez HTTPS en production avec un reverse proxy

## Développement

Pour le développement local :
```bash
# Installer les dépendances
pip install -r requirements.txt

# Configurer les variables d'environnement
export VK_SECRET_KEY="your-secret-key"
export VK_ADMIN_USERNAME="admin"
# ... autres variables

# Lancer l'application
python app/main.py
```

## Support

Pour les problèmes ou questions :
- Vérifiez les logs avec `docker-compose logs voight-kampff`
- Assurez-vous que toutes les variables d'environnement sont configurées
- Vérifiez que le port 8080 n'est pas utilisé par un autre service