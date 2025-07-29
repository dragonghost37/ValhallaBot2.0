# ValhallaBot2 🛡️

**A comprehensive Discord/Twitch integration bot for the Valhalla Gaming community**

ValhallaBot2 manages a gamified ranking system where Discord users link their Twitch accounts, earn points through community engagement, and climb through Norse-themed ranks.

## 🎯 Features

### Core Features
- **🔗 Twitch Integration**: Link Discord accounts to Twitch usernames
- **⚔️ Point System**: Earn points through chat participation and raids
- **🏆 Dynamic Ranking**: Automatic rank updates based on point percentiles
- **📊 Live Stream Monitoring**: Real-time notifications when members go live
- **📈 Comprehensive Stats**: Detailed user and community analytics

### Bonus Systems
- **🎁 Welcome Bonus**: 100 points for first-time Twitch linking
- **🤝 Referral System**: 200 points when referred users reach 400 points
- **💬 Chat Rewards**: Variable points based on streamer rank (1-6 points per message)
- **⚔️ Raid Rewards**: 10 points per viewer raided (with limits)

### Norse-Themed Ranks
- **🦾 Allfather** - Top 5% (6 points/message)
- **🛡️ Chieftain** - Top 5-15% (5 points/message)
- **🦅 Jarl** - Top 15-30% (4 points/message)
- **🐺 Berserker** - Top 30-50% (3 points/message)
- **🛶 Raider** - Top 50-80% (2 points/message)
- **🪓 Thrall** - Bottom 20% (1 point/message)

## 📋 Prerequisites

### System Requirements
- **Python 3.8+**
- **PostgreSQL Database**
- **Web Server** (for webhooks)

### Required Accounts & Tokens
- **Discord Bot Application** ([Discord Developer Portal](https://discord.com/developers/applications))
- **Twitch Application** ([Twitch Developer Console](https://dev.twitch.tv/console))
- **PostgreSQL Database** ([Heroku Postgres](https://devcenter.heroku.com/articles/heroku-postgresql) or self-hosted)

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ValhallaBot
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

4. Set up the database:
```bash
# Create PostgreSQL database
createdb valhallabot

# The bot will automatically create tables on first run
```

5. Run the bot:
```bash
python ValhallaBot2.py
```

## Configuration

### Required Environment Variables

- `DISCORD_BOT_TOKEN`: Your Discord bot token
- `TWITCH_CLIENT_ID`: Twitch application client ID
- `TWITCH_CLIENT_SECRET`: Twitch application client secret
- `TWITCH_EVENTSUB_SECRET`: Secret for Twitch EventSub webhooks
- `DATABASE_URL`: PostgreSQL connection string
- `WEBHOOK_URL`: Public URL for receiving webhooks

### Optional Environment Variables

- `ENVIRONMENT`: development/production (default: development)
- `LOG_LEVEL`: Logging level (default: INFO)
- `WEBHOOK_PORT`: Port for webhook server (default: 8080)
- `DEV_MODE`: Enable development mode (default: false)

## Commands

### User Commands

- `/linktwitch <username>` - Link your Twitch account
- `/rank [user]` - Show rank information
- `/mypoints` - Show your detailed stats
- `/leaderboard [limit]` - Show top warriors
- `/stats [user]` - Show detailed warrior statistics
- `/refer <user>` - Refer a new member
- `/help` - Show all commands
- `/howtouse` - Comprehensive usage guide

### Admin Commands

- `/newmember_stats [days]` - View onboarding statistics
- `/award_missing_bonus` - Award missing bonus points to eligible members

## Rank System

Warriors are automatically ranked based on their percentile in the community:

- 🦾 **Allfather** - Top 5% (6 points per chat)
- 🛡️ **Chieftain** - Top 15% (5 points per chat)
- 🦅 **Jarl** - Top 30% (4 points per chat)
- 🐺 **Berserker** - Top 50% (3 points per chat)
- 🛶 **Raider** - Top 80% (2 points per chat)
- 🪓 **Thrall** - Bottom 20% (1 point per chat)

## Architecture

### Core Components

- **ValhallaBot2.py**: Main application entry point
- **config.py**: Configuration management
- **validators.py**: Input validation and sanitization
- **monitoring.py**: Metrics, performance monitoring, health checks
- **error_handling.py**: Error handling, retry logic, database management
- **security.py**: Security middleware and utilities

### Database Schema

- **users**: User profiles and ranks
- **raids**: Raid event tracking
- **chat_points**: Chat point awards with audit trail
- **chats**: Chat statistics
- **referrals**: Referral tracking
- **audit_log**: Security and action auditing

### API Endpoints

- `GET /health` - Basic health check
- `GET /health/live` - Liveness probe
- `GET /health/ready` - Readiness probe
- `GET /status` - Comprehensive status report
- `POST /eventsub` - Twitch EventSub webhook endpoint

## Security Features

- Input validation and sanitization
- SQL injection prevention
- Rate limiting and IP blocking
- Webhook signature verification
- Circuit breaker pattern for external APIs
- Comprehensive audit logging
- Security event monitoring

## Monitoring

The bot includes comprehensive monitoring:

- **Metrics**: Counters, gauges, histograms
- **Performance**: Request tracking and timing
- **Health Checks**: Component health monitoring
- **Error Tracking**: Centralized error handling
- **Alerts**: Configurable alerting system

## Development

### Running in Development Mode

```bash
export DEV_MODE=true
export TEST_GUILD_ID=your_test_guild_id
python ValhallaBot2.py
```

### Testing

```bash
# Run tests (when available)
python -m pytest tests/
```

## Deployment

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

CMD ["python", "ValhallaBot2.py"]
```

### Environment Variables for Production

Ensure all required environment variables are set in your production environment. Use secure secret management for sensitive values.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

[Add your license information here]

## Support

For support, please [add contact information or issue tracker link].
