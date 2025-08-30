## 📢 Teneo Community Node BOT - v2.0!

<div align="center">
  <p align="center">
    <a href="https://t.me/D3_vin">
      <img src="https://img.shields.io/badge/Telegram-Channel-blue?style=for-the-badge&logo=telegram" alt="Telegram Channel">
    </a>
    <a href="https://t.me/D3vin_chat">
      <img src="https://img.shields.io/badge/Telegram-Chat-blue?style=for-the-badge&logo=telegram" alt="Telegram Chat">
    </a>
  </p>
</div>

<div align="center">
  <p align="center">
    <strong>🌐 Language</strong>: <a href="README.md">English</a> | <a href="README_RU.md">Русский</a>
  </p>
</div>

## 📢 Connect with Us

- **📢 Channel**: [https://t.me/D3_vin](https://t.me/D3_vin) - Latest updates and releases
- **💬 Chat**: [https://t.me/D3vin_chat](https://t.me/D3vin_chat) - Community support and discussions
- **📁 GitHub**: [https://github.com/D3-vin](https://github.com/D3-vin) - Source code and development

## 🚀 Features

- ✅ **Auto Registration** with email verification
- ✅ **Auto Authorization** and token management
- ✅ **Auto Get Account Information**
- ✅ **Auto Claim Referral Rewards**
- ✅ **Auto Claim Referral & Heartbeat Campaigns Rewards**
- ✅ **Auto Connect and Reconnect WebSocket**
- ✅ **Auto Receive Messages** every 15 minutes
- ✅ **Multi Accounts** with thread support
- ✅ **Proxy Support** for all operations
- ✅ **IMAP Support** for email operations
- ✅ **Smart Token Management System**
- ✅ **Wallet Connection** with smart account support
- ✅ **Twitter Integration** for campaigns
- ✅ **Discord Integration** for bonus rewards
- ✅ **SQLite Database** for account storage
- ✅ **YAML Configuration** files

## 📋 Requirements

- **Python 3.11+** and pip
- **Discord account** must be a member of the official Teneo group
- **Twitter account** for campaigns (optional)
- **Ethereum wallet** for connection (optional)

## 🛠️ Installation

### 1. Clone Repository
```bash
git clone https://github.com/D3-vin/Teneo-BOT.git
cd Teneo-BOT
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
# or
pip3 install -r requirements.txt
```

## ⚙️ Configuration

### 1. Create Data Folder
```bash
mkdir data
```

### 2. Configuration Setup
Copy and edit `config/config.yaml`:

```yaml
general:
  invite_code: "Svaag"           # Your invite code
  max_threads: 10                # Maximum number of threads

captcha:
  service: "2captcha"            # Service: 2captcha, capmonster, cflsolver
  api_key: "your_api_key_here"   # Your API key

mail:
  use_proxy_for_imap: false      # Use proxy for IMAP
  imap_settings:                  # IMAP server settings
    gmail.com: "imap.gmail.com"
    hotmail.com: "imap-mail.outlook.com"
    # Add other providers as needed

logging:
  level: "INFO"                  # Logging level
  rotation: "1 day"              # Log rotation
  retention: "7 days"            # Log retention
```

### 3. Create Account Files

#### Registration (`data/reg.txt`)
```
email1@example.com:password1
email2@example.com:password2
```

#### Authorization (`data/auth.txt`)
```
email1@example.com:password1
email2@example.com:password2
```

#### Farming (`data/farm.txt`)
```
email1@example.com:password1
email2@example.com:password2
```

#### Wallet Connection (`data/wallet.txt`)
```
email1@example.com:password1:private_key1
email2@example.com:password2:private_key2
```

#### Twitter Campaigns (`data/twitter.txt`)
```
email1@example.com:password1:private_key1:twitter_token1
email2@example.com:password2:private_key2:twitter_token2
```

#### Discord Integration (`data/discord.txt`)
```
email1@example.com:password1:private_key1:discord_token1
email2@example.com:password2:private_key2:discord_token2
```

**⚠️ IMPORTANT for Discord:** Account must be a member of the official Teneo group for proper integration.

#### Proxies (`data/proxy.txt`)
```
ip:port                    # HTTP by default
protocol://ip:port         # Specify protocol
protocol://user:pass@ip:port  # With authentication
```

**Supported protocols:** `http`, `https`, `socks4`, `socks5`

## 🔄 Migration from JSON to Database

If you have an old `data/accounts.json` file, run migration:

```bash
python migrate_json-to-db.py
```

**What happens during migration:**
- Data from `data/accounts.json` is transferred to SQLite database
- Creates `accounts` table with fields: `id`, `email`, `token`
- Old JSON file remains untouched
- Migration logs are saved to console

**Database structure:**
```sql
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    token TEXT
);
```

## 🚀 Usage

```bash
python bot.py
# or
python3 bot.py
```

## 📱 Operation Modes

### 1. **Registration**
- Automatic email verification via IMAP
- Saves successful registrations to `result/good_reg.txt`
- Saves failed attempts to `result/bad_reg.txt`
- Automatically saves tokens to database

### 2. **Authorization**
- Gets and saves tokens
- Saves successful authorizations to `result/good_auth.txt`
- Saves failed attempts to `result/bad_auth.txt`

### 3. **Farming**
- Connects to WebSocket for earning points
- Automatic reconnection on disconnects
- Real-time points and heartbeat tracking

### 4. **Wallet Connection**
- Connects cryptocurrency wallets to accounts
- Creates smart accounts for connected wallets
- Uses private keys from `data/wallet.txt`
- Automatic authorization if needed
- Checks existing connections

### 5. **Twitter Campaigns**
- Connects Twitter accounts to Teneo platform
- Automatically claims X campaign rewards
- Uses accounts from `data/twitter.txt`
- Requires wallet signature for form submission

### 6. **Discord Integration**
- Connects Discord accounts to Teneo platform
- **Requirement:** Account must be a member of the official Teneo group
- Automatically claims Discord integration bonuses
- Uses accounts from `data/discord.txt`

### 7. **Exit**
- Properly exits the program

## 📊 Results

The bot creates a `result` folder with the following files:

| File | Description |
|------|-------------|
| `good_reg.txt` | Successfully registered accounts |
| `bad_reg.txt` | Failed registration attempts |
| `good_auth.txt` | Successfully authorized accounts |
| `bad_auth.txt` | Failed authorization attempts |
| `good_farm.txt` | Successfully farming accounts |
| `bad_farm.txt` | Failed farming attempts |
| `good_wallet.txt` | Successfully connected wallets |
| `bad_wallet.txt` | Failed wallet connections |
| `good_twitter.txt` | Successfully connected Twitter accounts |
| `bad_twitter.txt` | Failed Twitter connections |
| `error_twitter.txt` | Detailed Twitter operation error logs |
| `good_discord.txt` | Successfully connected Discord accounts |
| `bad_discord.txt` | Failed Discord connections |

**Tokens and account data** are stored in SQLite database `data/database/database.sqlite3`.

## 🔧 Supported Captcha Services

- **2captcha** - Popular captcha solving service
- **CapMonster** - Alternative service
- **CFLSolver** - Local solving service

## 📧 Supported Email Providers

- Gmail, Hotmail, Outlook
- Mail.ru, Rambler, Yandex
- Yahoo, GMX, Onet
- And many others with configurable IMAP servers

## 📱 Telegram

- **Channel:** [@D3_vin](https://t.me/D3_vin)
- **Chat:** [@D3vin_chat](https://t.me/D3vin_chat)

## 🤝 Contributing

Don't forget to ⭐ star the repository and subscribe to the channel!

If you have questions, found a bug, or want to suggest improvements, create an issue in this GitHub repository or contact the developer.

## 📝 License

This project is intended for educational purposes. Use at your own risk.

---

**Version:** 2.0+  
**Support:** Python 3.11+

