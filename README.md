# Voight-Kampff Authentication Service

**Voight-Kampff** - Named after the empathy test from Philip K. Dick's "Do Androids Dream of Electric Sheep?" and the Blade Runner universe, this authentication service distinguishes between legitimate users and unauthorized entities through API key validation.

A standalone API key authentication service built with Flask and SQLite.

## Overview

Voight-Kampff is a lightweight authentication service that provides:
- User management with web interface
- API key generation and validation
- Secure authentication system
- Administrative interface
- Integrated SQLite database

## Installation and Quick Start

### Prerequisites
- Docker
- Docker Compose

### Getting Started

1. **Clone or copy the voight-kampff directory**

2. **Configure the environment**
   ```bash
   cd voight-kampff
   cp .env.example .env
   ```

3. **Generate a secure secret key**
   ```bash
   python3 -c "import secrets; print(secrets.token_urlsafe(64))"
   ```

4. **Edit the .env file with your values**
   - Replace `VK_SECRET_KEY` with the generated key
   - Configure admin credentials (`VK_ADMIN_USERNAME`, `VK_ADMIN_PASSWORD`, `VK_ADMIN_EMAIL`)

5. **Start the service**
   ```bash
   docker-compose up -d
   ```

6. **Access the service**
   - Web interface: http://localhost:8080
   - Login with the configured admin credentials

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VK_ADMIN_USERNAME` | Initial admin username | - |
| `VK_ADMIN_PASSWORD` | Initial admin password | - |
| `VK_ADMIN_EMAIL` | Initial admin email | - |
| `VK_SECRET_KEY` | Secret key for sessions | - |
| `VK_SESSION_EXPIRE_HOURS` | Session expiration duration | 24 |
| `VK_DB_PATH` | Database file path | /data/voight-kampff.db |

### Volumes

- `./data:/data` - SQLite database storage
- `./config:/config` - Configuration files (optional)

## Usage

### Web Interface
1. Login with admin credentials
2. Create users
3. Generate API keys
4. Manage permissions

### API
The service exposes endpoints for:
- API key validation
- User management
- Authentication

## Maintenance

### Backup
```bash
# Backup the database
cp ./data/voight-kampff.db ./backups/voight-kampff-$(date +%Y%m%d).db
```

### Logs
```bash
# View logs
docker-compose logs voight-kampff

# Follow logs in real-time
docker-compose logs -f voight-kampff
```

### Updates
```bash
# Stop the service
docker-compose down

# Rebuild the image
docker-compose build

# Restart
docker-compose up -d
```

## Security

- Use strong passwords for admin accounts
- Generate a unique secret key for each installation
- Regularly backup the database
- Monitor access logs
- Use HTTPS in production with a reverse proxy

## Development

For local development:
```bash
# Install dependencies
pip install -r requirements.txt

# Configure environment variables
export VK_SECRET_KEY="your-secret-key"
export VK_ADMIN_USERNAME="admin"
# ... other variables

# Run the application
python app/main.py
```

## Support

For issues or questions:
- Check logs with `docker-compose logs voight-kampff`
- Ensure all environment variables are configured
- Verify that port 8080 is not used by another service