# ValhallaBot2 Deployment Guide 🚀

This guide covers deploying ValhallaBot2 to various platforms and environments.

## 📋 Pre-Deployment Checklist

### Required Accounts & Setup
- [ ] Discord Bot Application created and token obtained
- [ ] Twitch Application registered with Client ID/Secret
- [ ] PostgreSQL database setup and connection string ready
- [ ] Public domain/URL for webhook endpoints
- [ ] SSL certificate for webhook security

### Discord Server Setup
- [ ] Bot added to server with proper permissions
- [ ] Required channels created:
  - `╡valhallabot-link` (for account linking)
  - `╡bot-commands` (for notifications)
  - `╡now-live` (for stream announcements)
  - `╡stream-summaries` (for post-stream summaries)
  - `╡streams-live` (for live dashboard)
- [ ] Rank roles created: `Allfather`, `Chieftain`, `Jarl`, `Berserker`, `Raider`, `Thrall`

### Environment Variables
Copy `.env.example` to `.env` and configure all required variables.

---

## 🐳 Docker Deployment (Recommended)

### 1. Create Dockerfile
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 botuser && chown -R botuser:botuser /app
USER botuser

# Expose port for webhooks
EXPOSE 8080

# Run the bot
CMD ["python", "ValhallaBot2.py"]
```

### 2. Create docker-compose.yml
```yaml
version: '3.8'

services:
  valhallabot:
    build: .
    ports:
      - "8080:8080"
    env_file:
      - .env
    depends_on:
      - postgres
    restart: unless-stopped
    volumes:
      - ./logs:/app/logs

  postgres:
    image: postgres:15
    environment:
      POSTGRES_DB: valhallabot
      POSTGRES_USER: botuser
      POSTGRES_PASSWORD: secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

volumes:
  postgres_data:
```

### 3. Deploy
```bash
# Build and start
docker-compose up -d

# View logs
docker-compose logs -f valhallabot

# Stop
docker-compose down
```

---

## 🚢 Heroku Deployment

### 1. Setup Heroku CLI
```bash
# Install Heroku CLI
# https://devcenter.heroku.com/articles/heroku-cli

# Login
heroku login
```

### 2. Create Heroku App
```bash
# Create app
heroku create your-valhallabot-app

# Add PostgreSQL addon
heroku addons:create heroku-postgresql:mini

# Set buildpack
heroku buildpacks:set heroku/python
```

### 3. Configure Environment Variables
```bash
# Discord
heroku config:set DISCORD_BOT_TOKEN=your_token

# Twitch
heroku config:set TWITCH_CLIENT_ID=your_client_id
heroku config:set TWITCH_CLIENT_SECRET=your_secret
heroku config:set TWITCH_BOT_TOKEN=your_bot_token

# Webhook
heroku config:set WEBHOOK_URL=https://your-app.herokuapp.com/eventsub
heroku config:set EVENTSUB_SECRET=your_webhook_secret

# Database URL is automatically set by Heroku Postgres
```

### 4. Create Procfile
```
web: python ValhallaBot2.py
```

### 5. Deploy
```bash
# Initialize git and deploy
git init
git add .
git commit -m "Initial deployment"
git remote add heroku https://git.heroku.com/your-valhallabot-app.git
git push heroku main

# View logs
heroku logs --tail
```

---

## 🖥️ VPS/Dedicated Server Deployment

### 1. Server Setup (Ubuntu/Debian)
```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv nginx postgresql postgresql-contrib certbot python3-certbot-nginx

# Create user for bot
sudo useradd -m -s /bin/bash valhallabot
sudo -u valhallabot -i
```

### 2. Application Setup
```bash
# Clone repository
git clone https://github.com/dragonghost37/ValhallaBot.git
cd ValhallaBot/ValhallaBot2-Clean

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration
```

### 3. Database Setup
```bash
# Switch to postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE valhallabot;
CREATE USER botuser WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE valhallabot TO botuser;
\q
```

### 4. Create Systemd Service
```bash
sudo nano /etc/systemd/system/valhallabot.service
```

```ini
[Unit]
Description=ValhallaBot2 Discord Bot
After=network.target postgresql.service

[Service]
Type=simple
User=valhallabot
WorkingDirectory=/home/valhallabot/ValhallaBot/ValhallaBot2-Clean
Environment=PATH=/home/valhallabot/ValhallaBot/ValhallaBot2-Clean/venv/bin
ExecStart=/home/valhallabot/ValhallaBot/ValhallaBot2-Clean/venv/bin/python ValhallaBot2.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

### 5. Nginx Configuration
```bash
sudo nano /etc/nginx/sites-available/valhallabot
```

```nginx
server {
    listen 80;
    server_name your-domain.com;

    location /eventsub {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location / {
        return 301 https://your-domain.com$request_uri;
    }
}
```

### 6. SSL Certificate
```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/valhallabot /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Get SSL certificate
sudo certbot --nginx -d your-domain.com

# Start services
sudo systemctl enable valhallabot
sudo systemctl start valhallabot
sudo systemctl status valhallabot
```

---

## ☁️ Cloud Platform Deployment

### Railway
1. Connect GitHub repository
2. Add PostgreSQL plugin
3. Set environment variables
4. Deploy automatically

### Render
1. Create new Web Service
2. Connect GitHub repository
3. Add PostgreSQL database
4. Configure environment variables
5. Deploy

### DigitalOcean App Platform
1. Create new app from GitHub
2. Add managed PostgreSQL database
3. Set environment variables
4. Deploy

---

## 🔧 Webhook Setup

### Twitch EventSub Configuration
```python
# Example webhook registration (run once)
import aiohttp
import asyncio

async def register_webhook():
    headers = {
        'Client-ID': 'your_client_id',
        'Authorization': 'Bearer your_app_access_token',
        'Content-Type': 'application/json'
    }
    
    data = {
        'type': 'channel.raid',
        'version': '1',
        'condition': {
            'to_broadcaster_user_id': 'user_id_here'
        },
        'transport': {
            'method': 'webhook',
            'callback': 'https://your-domain.com/eventsub',
            'secret': 'your_webhook_secret'
        }
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.post(
            'https://api.twitch.tv/helix/eventsub/subscriptions',
            headers=headers,
            json=data
        ) as resp:
            result = await resp.json()
            print(result)

# Run for each user you want to monitor
asyncio.run(register_webhook())
```

---

## 📊 Monitoring & Maintenance

### Health Checks
```bash
# Check bot status
systemctl status valhallabot

# View logs
journalctl -u valhallabot -f

# Check database
sudo -u postgres psql valhallabot -c "SELECT COUNT(*) FROM users;"
```

### Log Rotation
```bash
# Create logrotate config
sudo nano /etc/logrotate.d/valhallabot
```

```
/home/valhallabot/ValhallaBot/ValhallaBot2-Clean/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    copytruncate
}
```

### Backup Script
```bash
#!/bin/bash
# backup.sh
pg_dump $DATABASE_URL > backup_$(date +%Y%m%d_%H%M%S).sql
aws s3 cp backup_*.sql s3://your-backup-bucket/
rm backup_*.sql
```

---

## 🚨 Troubleshooting

### Common Issues

**Bot not starting:**
```bash
# Check logs
journalctl -u valhallabot -n 50

# Test configuration
source venv/bin/activate
python -c "import os; print(os.getenv('DISCORD_BOT_TOKEN'))"
```

**Database connection errors:**
```bash
# Test database connection
psql $DATABASE_URL -c "SELECT version();"
```

**Webhook not receiving events:**
- Verify public URL accessibility
- Check SSL certificate validity
- Confirm webhook secret matches
- Test with curl:
```bash
curl -X POST https://your-domain.com/eventsub \
  -H "Content-Type: application/json" \
  -d '{"challenge":"test"}'
```

### Performance Optimization
- Use connection pooling for database
- Implement Redis caching for frequent queries
- Add monitoring with Prometheus/Grafana
- Set up alerting for downtime

---

## 🔄 Updates & Maintenance

### Updating the Bot
```bash
# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt

# Restart service
sudo systemctl restart valhallabot
```

### Database Migrations
```bash
# Backup before migration
pg_dump $DATABASE_URL > pre_migration_backup.sql

# Run bot to auto-create new tables/columns
python ValhallaBot2.py
```

---

## 📞 Support

For deployment issues:
1. Check logs first
2. Verify environment variables
3. Test components individually
4. Create GitHub issue with logs
5. Contact development team

Remember: Always test in a development environment before deploying to production! 🛡️
