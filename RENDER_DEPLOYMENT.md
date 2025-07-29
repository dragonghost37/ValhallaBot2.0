# 🚀 ValhallaBot2 Render Deployment Guide

This guide will walk you through deploying ValhallaBot2 to Render, a modern cloud platform that's perfect for Discord bots.

## 🎯 Why Render?

- **Easy deployment** from GitHub
- **Automatic scaling** and health checks
- **Built-in PostgreSQL** database
- **Free tier available** for testing
- **HTTPS by default** for webhooks
- **Auto-deploy** on git push

## 📋 Prerequisites

Before deploying, ensure you have:

1. **GitHub Repository** with your ValhallaBot2 code
2. **Discord Bot Token** from Discord Developer Portal
3. **Twitch Application** credentials (Client ID, Client Secret, Bot Token)
4. **Render Account** (free at render.com)

## 🔧 Step 1: Prepare Your Repository

### 1.1 Ensure Required Files
Your repository should have these files:
- ✅ `ValhallaBot2.py` - Main bot application
- ✅ `requirements.txt` - Python dependencies
- ✅ `render.yaml` - Render service configuration
- ✅ `runtime.txt` - Python version specification

### 1.2 Verify render.yaml Configuration
The `render.yaml` file is already configured for you:

```yaml
services:
  # ValhallaBot2 Discord/Twitch Bot Service
  - type: web
    name: valhallabot2
    env: python
    plan: starter
    buildCommand: pip install -r requirements.txt
    startCommand: python ValhallaBot2.py
    # ... (environment variables and database config)
```

## 🌐 Step 2: Deploy to Render

### 2.1 Connect GitHub Repository
1. Go to [render.com](https://render.com) and sign up/log in
2. Click **"New"** → **"Blueprint"**
3. Connect your GitHub account
4. Select your ValhallaBot2 repository
5. Choose the branch (usually `main`)

### 2.2 Review Blueprint Configuration
Render will automatically detect your `render.yaml` file and show:
- **Web Service**: valhallabot2 (your bot)
- **Database**: valhallabot-db (PostgreSQL)

Click **"Apply"** to start the deployment.

## ⚙️ Step 3: Configure Environment Variables

After deployment starts, you'll need to set your bot credentials:

### 3.1 Required Environment Variables
Go to your service dashboard and add these environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `DISCORD_BOT_TOKEN` | Your Discord bot token | `MTIz...` |
| `TWITCH_CLIENT_ID` | Twitch application client ID | `abc123...` |
| `TWITCH_CLIENT_SECRET` | Twitch application client secret | `def456...` |
| `TWITCH_BOT_TOKEN` | Twitch bot OAuth token | `oauth:ghi789...` |

### 3.2 Auto-Generated Variables
These are automatically set by Render:
- `DATABASE_URL` - PostgreSQL connection string
- `WEBHOOK_URL` - Your webhook endpoint URL
- `EVENTSUB_SECRET` - EventSub verification secret
- `PORT` - Application port (8000)

### 3.3 Set Environment Variables
1. Click on your **valhallabot2** service
2. Go to **Environment** tab
3. Add each required variable
4. Click **"Save Changes"**

The service will automatically redeploy with new variables.

## 🗄️ Step 4: Database Setup

### 4.1 Automatic Database Creation
Render automatically:
- ✅ Creates PostgreSQL database
- ✅ Sets up connection string
- ✅ Initializes tables on first run

### 4.2 Verify Database Connection
Check your service logs for:
```
✅ Database initialized successfully
🛡️ Starting ValhallaBot2 on Render...
```

## 🔗 Step 5: Configure Twitch Webhooks

### 5.1 Get Your Webhook URL
Your webhook URL will be:
```
https://your-service-name.onrender.com/eventsub
```

Replace `your-service-name` with your actual Render service name.

### 5.2 Set Up Twitch EventSub
Use the Twitch CLI or API to register webhooks:

```bash
# Install Twitch CLI
# Subscribe to raid events
twitch api post eventsub/subscriptions \
  -b '{
    "type": "channel.raid",
    "version": "1",
    "condition": {
      "to_broadcaster_user_id": "YOUR_BROADCASTER_ID"
    },
    "transport": {
      "method": "webhook",
      "callback": "https://your-service-name.onrender.com/eventsub",
      "secret": "YOUR_EVENTSUB_SECRET"
    }
  }'
```

## 📊 Step 6: Monitor Your Deployment

### 6.1 Check Service Health
Monitor your deployment:
- **Service Logs**: Real-time application logs
- **Metrics**: CPU, memory, and response times
- **Health Checks**: Automatic endpoint monitoring

### 6.2 Health Check Endpoints
Your bot provides these endpoints:
- `/health` - Simple health check
- `/` - Bot status and statistics

### 6.3 View Logs
```bash
# Real-time logs
render logs --service=valhallabot2 --follow

# Or view in dashboard
# Go to Logs tab in your service
```

## 🛠️ Step 7: Verify Bot Functionality

### 7.1 Discord Connection
Check that your bot:
- ✅ Appears online in Discord
- ✅ Responds to slash commands
- ✅ Has proper permissions

### 7.2 Test Commands
Try these commands in your Discord:
```
/linktwitch your_username
/rank
/mypoints
/leaderboard
```

### 7.3 Test Webhooks
- Go live on Twitch
- Raid another channel
- Check Discord for notifications

## 🔄 Step 8: Automatic Updates

### 8.1 Auto-Deploy Setup
Render automatically redeploys when you:
- Push to your connected branch
- Update environment variables
- Modify render.yaml

### 8.2 Manual Deploy
To manually trigger deployment:
1. Go to your service dashboard
2. Click **"Manual Deploy"**
3. Select **"Deploy latest commit"**

## 💰 Step 9: Scaling and Pricing

### 9.1 Free Tier Limits
Render's free tier includes:
- **Web Service**: 750 hours/month
- **Database**: 1GB storage, 1 CPU, 1GB RAM
- **Bandwidth**: 100GB/month

### 9.2 Upgrade Options
For production use, consider:
- **Starter Plan**: $7/month - Always on, custom domains
- **Standard Plan**: $25/month - More resources, backups
- **Pro Plan**: $85/month - High availability, priority support

## ⚠️ Troubleshooting

### Common Issues

#### Bot Won't Start
```bash
# Check logs for errors
render logs --service=valhallabot2

# Common fixes:
# 1. Verify all environment variables are set
# 2. Check Discord token is valid
# 3. Ensure database is running
```

#### Database Connection Errors
```bash
# Verify database service is running
# Check DATABASE_URL is properly set
# Look for PostgreSQL-specific errors in logs
```

#### Webhook Not Receiving Events
```bash
# Verify webhook URL is accessible
# Check EVENTSUB_SECRET matches Twitch configuration
# Ensure /eventsub endpoint is responding
```

### Debug Commands
```bash
# Check service status
render services list

# View specific service info
render services get valhallabot2

# Check environment variables
render env list --service=valhallabot2
```

## 🎉 Success!

Your ValhallaBot2 is now running on Render! Here's what you've accomplished:

✅ **Deployed** Discord/Twitch bot to cloud  
✅ **Configured** PostgreSQL database  
✅ **Set up** automatic scaling and health checks  
✅ **Enabled** Twitch webhook integration  
✅ **Implemented** continuous deployment  

## 📚 Next Steps

1. **Monitor Usage**: Watch your Render dashboard for performance
2. **Add Features**: Deploy new bot features via git push
3. **Scale Up**: Upgrade to paid plan if needed
4. **Backup**: Consider database backup strategy
5. **Security**: Review access logs and environment variables

## 🆘 Support

- **Render Docs**: [render.com/docs](https://render.com/docs)
- **Discord.py Docs**: [discordpy.readthedocs.io](https://discordpy.readthedocs.io)
- **Twitch API Docs**: [dev.twitch.tv](https://dev.twitch.tv)

Happy deploying! 🚀🛡️
