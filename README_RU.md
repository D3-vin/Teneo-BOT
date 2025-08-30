##📢 Teneo Community Node BOT - v2.0!

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

## 📢 Свяжитесь с нами

- **📢 Канал**: [https://t.me/D3_vin](https://t.me/D3_vin) - Последние обновления и релизы
- **💬 Чат**: [https://t.me/D3vin_chat](https://t.me/D3vin_chat) - Поддержка сообщества и обсуждения
- **📁 GitHub**: [https://github.com/D3-vin](https://github.com/D3-vin) - Исходный код и разработка

## 🚀 Возможности

- ✅ **Автоматическая регистрация** с верификацией email
- ✅ **Автоматическая авторизация** и управление токенами
- ✅ **Автоматическое получение информации об аккаунте**
- ✅ **Автоматическое получение реферальных наград**
- ✅ **Автоматическое получение наград за рефералов и кампании**
- ✅ **Автоматическое подключение и переподключение WebSocket**
- ✅ **Автоматический прием сообщений** каждые 15 минут
- ✅ **Мультиаккаунтность** с поддержкой потоков
- ✅ **Поддержка прокси** для всех операций
- ✅ **Поддержка IMAP** для работы с почтой
- ✅ **Умная система управления токенами**
- ✅ **Подключение кошельков** с поддержкой смарт-аккаунтов
- ✅ **Интеграция с Twitter** для кампаний
- ✅ **Интеграция с Discord** для получения бонусов
- ✅ **База данных SQLite** для хранения аккаунтов
- ✅ **Конфигурация через YAML** файлы

## 📋 Требования

- **Python 3.11+** и pip
- **Discord аккаунт** должен состоять в официальной группе Teneo
- **Twitter аккаунт** для кампаний (опционально)
- **Ethereum кошелек** для подключения (опционально)

## 🛠️ Установка

### 1. Клонирование репозитория
```bash
git clone https://github.com/D3-vin/Teneo-BOT.git
cd Teneo-BOT
```

### 2. Установка зависимостей
```bash
pip install -r requirements.txt
# или
pip3 install -r requirements.txt
```

## ⚙️ Конфигурация

### 1. Создание папки данных
```bash
mkdir data
```

### 2. Настройка конфигурации
Скопируйте и отредактируйте `config/config.yaml`:

```yaml
general:
  invite_code: "Svaag"           # Ваш пригласительный код
  max_threads: 10                # Максимальное количество потоков

captcha:
  service: "2captcha"            # Сервис: 2captcha, capmonster, cflsolver
  api_key: "your_api_key_here"   # Ваш API ключ

mail:
  use_proxy_for_imap: false      # Использовать прокси для IMAP
  imap_settings:                  # Настройки IMAP серверов
    gmail.com: "imap.gmail.com"
    hotmail.com: "imap-mail.outlook.com"
    # Добавьте другие провайдеры по необходимости

logging:
  level: "INFO"                  # Уровень логирования
  rotation: "1 day"              # Ротация логов
  retention: "7 days"            # Хранение логов
```

### 3. Создание файлов с аккаунтами

#### Регистрация (`data/reg.txt`)
```
email1@example.com:password1
email2@example.com:password2
```

#### Авторизация (`data/auth.txt`)
```
email1@example.com:password1
email2@example.com:password2
```

#### Фарминг (`data/farm.txt`)
```
email1@example.com:password1
email2@example.com:password2
```

#### Подключение кошельков (`data/wallet.txt`)
```
email1@example.com:password1:private_key1
email2@example.com:password2:private_key2
```

#### Twitter кампании (`data/twitter.txt`)
```
email1@example.com:password1:private_key1:twitter_token1
email2@example.com:password2:private_key2:twitter_token2
```

#### Discord интеграция (`data/discord.txt`)
```
email1@example.com:password1:private_key1:discord_token1
email2@example.com:password2:private_key2:discord_token2
```

**⚠️ ВАЖНО для Discord:** Аккаунт должен состоять в официальной группе Teneo для корректной работы интеграции.

#### Прокси (`data/proxy.txt`)
```
ip:port                    # HTTP по умолчанию
protocol://ip:port         # Указание протокола
protocol://user:pass@ip:port  # С аутентификацией
```

**Поддерживаемые протоколы:** `http`, `https`, `socks4`, `socks5`

## 🔄 Миграция с JSON в базу данных

Если у вас есть старый файл `data/accounts.json`, выполните миграцию:

```bash
python migrate_json-to-db.py
```

**Что происходит при миграции:**
- Данные из `data/accounts.json` переносятся в SQLite базу
- Создается таблица `accounts` с полями: `id`, `email`, `token`
- Старый файл JSON остается нетронутым
- Логи миграции сохраняются в консоли

**Структура базы данных:**
```sql
CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    token TEXT
);
```

## 🚀 Запуск

```bash
python bot.py
# или
python3 bot.py
```

## 📱 Режимы работы

### 1. **Регистрация**
- Автоматическая верификация email через IMAP
- Сохранение успешных регистраций в `result/good_reg.txt`
- Сохранение неудачных попыток в `result/bad_reg.txt`
- Автоматическое сохранение токенов в базу данных

### 2. **Авторизация**
- Получение и сохранение токенов
- Сохранение успешных авторизаций в `result/good_auth.txt`
- Сохранение неудачных попыток в `result/bad_auth.txt`

### 3. **Фарминг**
- Подключение к WebSocket для заработка очков
- Автоматическое переподключение при разрывах
- Отслеживание очков и heartbeat в реальном времени

### 4. **Подключение кошельков**
- Подключение криптокошельков к аккаунтам
- Создание смарт-аккаунтов для подключенных кошельков
- Использование приватных ключей из `data/wallet.txt`
- Автоматическая авторизация при необходимости
- Проверка существующих подключений

### 5. **Twitter кампании**
- Подключение Twitter аккаунтов к платформе Teneo
- Автоматическое получение наград за X кампании
- Использование аккаунтов из `data/twitter.txt`
- Требуется подпись кошелька для отправки форм

### 6. **Discord интеграция**
- Подключение Discord аккаунтов к платформе Teneo
- **Требование:** Аккаунт должен состоять в официальной группе Teneo
- Автоматическое получение бонусов за Discord интеграцию
- Использование аккаунтов из `data/discord.txt`

### 7. **Выход**
- Корректное завершение программы

## 📊 Результаты

Бот создает папку `result` со следующими файлами:

| Файл | Описание |
|------|----------|
| `good_reg.txt` | Успешно зарегистрированные аккаунты |
| `bad_reg.txt` | Неудачные попытки регистрации |
| `good_auth.txt` | Успешно авторизованные аккаунты |
| `bad_auth.txt` | Неудачные попытки авторизации |
| `good_farm.txt` | Успешно фармящие аккаунты |
| `bad_farm.txt` | Неудачные попытки фарминга |
| `good_wallet.txt` | Успешно подключенные кошельки |
| `bad_wallet.txt` | Неудачные подключения кошельков |
| `good_twitter.txt` | Успешно подключенные Twitter аккаунты |
| `bad_twitter.txt` | Неудачные подключения Twitter |
| `error_twitter.txt` | Детальные логи ошибок Twitter операций |
| `good_discord.txt` | Успешно подключенные Discord аккаунты |
| `bad_discord.txt` | Неудачные подключения Discord |

**Токены и данные аккаунтов** сохраняются в SQLite базе данных `data/database/database.sqlite3`.

## 🔧 Поддерживаемые сервисы капчи

- **2captcha** - Популярный сервис решения капчи
- **CapMonster** - Альтернативный сервис
- **CFLSolver** - Локальный сервис решения

## 📧 Поддерживаемые почтовые провайдеры

- Gmail, Hotmail, Outlook
- Mail.ru, Rambler, Yandex
- Yahoo, GMX, Onet
- И многие другие с настраиваемыми IMAP серверами

## 📱 Telegram

- **Канал:** [@D3_vin](https://t.me/D3_vin)
- **Чат:** [@D3vin_chat](https://t.me/D3vin_chat)

## 🤝 Вклад в проект

Не забудьте поставить ⭐ звезду репозиторию и подписаться на канал!

Если у вас есть вопросы, нашли ошибку или хотите предложить улучшения, создайте issue в этом GitHub репозитории или свяжитесь с разработчиком.

## 📝 Лицензия

Этот проект предназначен для образовательных целей. Используйте на свой страх и риск.

---

**Версия:** 2.0+  
**Поддержка:** Python 3.11+
