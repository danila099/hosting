import logging
from telegram import Update, Bot
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, MessageHandler, filters
import json
import os

TELEGRAM_TOKEN = 'YOUR token_bot'  # <-- Вставьте сюда свой токен
CHAT_IDS_FILE = 'telegram_chat_ids.json'

def load_chat_ids():
    if not os.path.exists(CHAT_IDS_FILE):
        return []
    with open(CHAT_IDS_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_chat_ids(chat_ids):
    with open(CHAT_IDS_FILE, 'w', encoding='utf-8') as f:
        json.dump(chat_ids, f, ensure_ascii=False, indent=2)

def add_chat_id(chat_id):
    chat_ids = load_chat_ids()
    if chat_id not in chat_ids:
        chat_ids.append(chat_id)
        save_chat_ids(chat_ids)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    add_chat_id(chat_id)
    await update.message.reply_text('🌑 Привет! Я бот для уведомлений о состоянии вашего сервера.')

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text('Пока что я только отправляю уведомления. В будущем — больше команд!')

async def echo(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    add_chat_id(chat_id)
    await update.message.reply_text('Я запомнил ваш chat_id для уведомлений.')

def send_telegram_notification(text, dark_theme=True):
    from telegram import Bot
    chat_ids = load_chat_ids()
    bot = Bot(token=TELEGRAM_TOKEN)
    if dark_theme:
        text = f"🌑 <b>{text}</b>"
        parse_mode = "HTML"
    else:
        parse_mode = None
    for chat_id in chat_ids:
        try:
            bot.send_message(chat_id=chat_id, text=text, parse_mode=parse_mode)
        except Exception as e:
            print(f"Ошибка отправки в chat_id {chat_id}: {e}")

def main():
    logging.basicConfig(level=logging.INFO)
    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler('start', start))
    app.add_handler(CommandHandler('status', status))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, echo))
    print('Бот запущен!')
    app.run_polling()

if __name__ == '__main__':
    main() 
