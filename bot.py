import logging
import re
import os
import paramiko
import psycopg2
import subprocess

from psycopg2 import Error
from dotenv import load_dotenv
from telegram import Update, ForceReply
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, ConversationHandler

load_dotenv()

TOKEN = os.getenv("TOKEN")
RM_HOST = os.getenv("RM_HOST")
RM_PORT = os.getenv("RM_PORT")
RM_USER = os.getenv("RM_USER")
RM_PASSWORD = os.getenv("RM_PASSWORD")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_DATABASE = os.getenv("DB_DATABASE")
DB_REPL_USER = os.getenv("DB_REPL_USER")
DB_REPL_PASSWORD = os.getenv("DB_REPL_PASSWORD")
DB_REPL_HOST = os.getenv("DB_REPL_HOST")
DB_REPL_PORT = os.getenv("DB_REPL_PORT")

logging.basicConfig(
    filename='logfile.txt', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO
)
logger = logging.getLogger(__name__)
paramiko.util.log_to_file("paramiko.log")

found_phone_numbers = []
found_emails = []

def start(update: Update, context):
    user = update.effective_user
    update.message.reply_text(f'Привет {user.full_name}!')

def helpCommand(update: Update, context):
    help_text = """ 
    /start - Запуск бота
    /help - Получить информацию о доступных командах
    /findPhoneNumber - Поиск телефонных номеров в тексте 
    /findEmail - Поиск email-адресов в тексте
    /verify_password - Проверка сложности пароля
    /get_release - Получить информацию о релизе системы
    /get_uname - Получить информацию об архитектуру процессора, имени хоста системы и версии ядра
    /get_uptime - Получить информацию о времени работы
    /get_df - Сбор информации о состоянии файловой системы
    /get_free - Сбор информации о состоянии оперативной памяти
    /get_mpstat -  Сбор информации о производительности системы
    /get_w - Сбор информации о работающих в данной системе пользователях
    /get_auths - Сбор логов (Последние 10 входов в систему)
    /get_critical - Сбор логов (Последние 5 критических событий)
    /get_ps - Сбор информации о запущенных процессах
    /get_ss - Сбор информации об используемых портах
    /get_apt_list - Сбор информации об установленных пакетах
    /get_services - Сбор информации о запущенных сервисах
    /get_repl_logs - Вывод логов 
    /get_emails - Получить email-адреса из БД
    /get_phone_numbers - Получить телефонные номера из БД
    """
    update.message.reply_text(help_text)

def findPhoneNumbersCommand(update: Update, context):
    update.message.reply_text('Введите текст для поиска телефонных номеров: ')
    return 'findPhoneNumbers'

def findPhoneNumbers(update: Update, context):
    global found_phone_numbers  

    user_input = update.message.text 
    phoneNumRegex = re.compile(r'(\+7|8)[\s-]?(\(?\d{3}\)?)[\s-]?(\d{3})[\s-]?(\d{2})[\s-]?(\d{2})')
    found_phone_numbers = phoneNumRegex.findall(user_input)

    if not found_phone_numbers: 
        update.message.reply_text('Телефонные номера не найдены')
        return ConversationHandler.END 
    
    phoneNumbers = ''
    for i, match in enumerate(found_phone_numbers):
        formatted_number = f'{match[0]} {match[1]} {match[2]} {match[3]} {match[4]}'
        phoneNumbers += f'{i + 1}. {formatted_number}\n'
        
    update.message.reply_text(f'Найденные номера:\n{phoneNumbers}')
    update.message.reply_text('Хотите сохранить эти номера в базу данных? (да/нет)')
    
    return 'savePhoneNumbers'

def savePhoneNumbers(update: Update, context):
    response = update.message.text.lower()
    
    if response == 'да':
        try:
            connection = psycopg2.connect(
                user=DB_USER,
                password=DB_PASSWORD,
                host=DB_HOST,
                port=DB_PORT,
                database=DB_DATABASE
            )
            cursor = connection.cursor()
            for number in found_phone_numbers:
                formatted_number = f'{number[0]} {number[1]} {number[2]} {number[3]} {number[4]}'
                cursor.execute("INSERT INTO phone_numbers (phone_number) VALUES (%s)", (formatted_number,))
            connection.commit()
            update.message.reply_text('Номера успешно сохранены в базу данных.')
        except (Exception, Error) as error:
            logger.error(f"Ошибка при работе с PostgreSQL: {error}")
            update.message.reply_text('Произошла ошибка при сохранении номеров.')
        finally:
            if connection:
                cursor.close()
                connection.close()
    else:
        update.message.reply_text('Сохранение номеров отменено.')

    return ConversationHandler.END

def findEmailCommand(update: Update, context):
    update.message.reply_text('Введите текст для поиска email адресов: ')
    return 'findEmail'

def findEmail(update: Update, context):
    global found_emails  

    user_input = update.message.text 
    emailRegex = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    found_emails = emailRegex.findall(user_input)

    if not found_emails: 
        update.message.reply_text('Email адреса не найдены')
        return ConversationHandler.END

    emails = '\n'.join(found_emails)
    
    update.message.reply_text(f'Найденные email адреса:\n{emails}')
    update.message.reply_text('Хотите сохранить эти email адреса в базу данных? (да/нет)')
    
    return 'saveEmail'

def saveEmail(update: Update, context):
    response = update.message.text.lower()
    
    if response == 'да':
        try:
            connection = psycopg2.connect(
                user=DB_USER,
                password=DB_PASSWORD,
                host=DB_HOST,
                port=DB_PORT,
                database=DB_DATABASE
            )
            cursor = connection.cursor()
            for email in found_emails:
                cursor.execute("INSERT INTO email_addresses (email) VALUES (%s)", (email,))
            connection.commit()
            update.message.reply_text('Email адреса успешно сохранены в базу данных.')
        except (Exception, Error) as error:
            logger.error(f"Ошибка при работе с PostgreSQL: {error}")
            update.message.reply_text('Произошла ошибка при сохранении email адресов.')
        finally:
            if connection:
                cursor.close()
                connection.close()
    else:
        update.message.reply_text('Сохранение email адресов отменено.')

    return ConversationHandler.END
    
def verifyPasswordCommand(update: Update, context):
    update.message.reply_text('Введите пароль для проверки:')
    return 'verifyPassword'

def verifyPassword(update: Update, context):
    password = update.message.text
    
    passwordRegex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()]).{8,}$')

    if passwordRegex.match(password):
        update.message.reply_text('Пароль сложный')
    else:
        update.message.reply_text('Пароль простой')
    
    return ConversationHandler.END  

def echo(update: Update, context):
    update.message.reply_text(update.message.text)

def ssh_connect():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(RM_HOST, port=int(RM_PORT), username=RM_USER, password=RM_PASSWORD)
    return client

def ssh_connect_db():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(DB_HOST, port=int(RM_PORT), username=DB_USER, password=DB_PASSWORD, look_for_keys=False)
    return client

def execute_command(command):
    client = ssh_connect()
    stdin, stdout, stderr = client.exec_command(command)
    output = stdout.read().decode()
    error = stderr.read().decode()
    client.close()
    
    if error:
        return f"Ошибка: {error}"
    return output.strip()

def get_release(update: Update, context):
    output = execute_command('lsb_release -a')
    update.message.reply_text(output)

def get_uname(update: Update, context):
    output = execute_command('uname -a')
    update.message.reply_text(output)

def get_uptime(update: Update, context):
    output = execute_command('uptime')
    update.message.reply_text(output)

def get_df(update: Update, context):
    output = execute_command('df -h')
    update.message.reply_text(output)

def get_free(update: Update, context):
    output = execute_command('free -h')
    update.message.reply_text(output)

def get_mpstat(update: Update, context):
    output = execute_command('mpstat')
    update.message.reply_text(output)

def get_w(update: Update, context):
    output = execute_command('w')
    update.message.reply_text(output)

def get_auths(update: Update, context):
    output = execute_command('last -n 10')
    update.message.reply_text(output)

def get_critical(update: Update, context):
    output = execute_command('journalctl -r -p crit -n 5 | head -n 10')
    update.message.reply_text(output)

def get_ps(update: Update, context):
    output = execute_command('ps')
    update.message.reply_text(output)

def get_ss(update: Update, context):
    output = execute_command('mpstat')
    update.message.reply_text(output)

def get_apt_list_command(update: Update, context):
    update.message.reply_text('Введите название пакета для поиска (введите "a" для получения списка всех установленных пакетов):')
    return 'get_apt_list'

def get_apt_list(update: Update, context):
    package_name = update.message.text.strip()
    
    if package_name == 'a':
        command = "dpkg --get-selections | head -n 50"
    else:
        command = f"dpkg --get-selections | grep -w {package_name}"

    result = execute_command(command)

    if result:
        update.message.reply_text(result)
    else:
        update.message.reply_text('Пакеты не найдены.')

    return ConversationHandler.END

def get_services(update: Update, context):
    output = execute_command('service --status-all')
    update.message.reply_text(output)

def get_repl_logs(update: Update, context):
    if DB_HOST == "" or DB_USER == "" or DB_PASSWORD == "":
        update.message.reply_text("Неверно заданы параметры подключения по SSH")
        return

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh_client.connect(
            hostname=DB_HOST,
            port=DB_PORT_SSH,
            username=DB_USER,
            password=DB_PASSWORD,
        )

        log_command = "tail -n 20 /var/log/postgresql/postgresql.log"
        stdin, stdout, stderr = ssh_client.exec_command(log_command)

        log_information = stdout.read().decode("utf-8")
        if log_information:
            update.message.reply_text(log_information)
        else:
            update.message.reply_text("log-файл пуст или не найден.")

    except Exception as error:
        update.message.reply_text(f"Ошибка подключения: {str(error)}")
    finally:
        ssh_client.close()

def get_emails(update: Update, context):
    connection = None
    try:
        connection = psycopg2.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT,
            database=DB_DATABASE
        )
        cursor = connection.cursor()
        cursor.execute("SELECT email FROM email_addresses;")
        emails = cursor.fetchall()

        if emails:
            email_list = "\n".join(email[0] for email in emails)
            update.message.reply_text(f'Список email-адресов:\n{email_list}')
        else:
            update.message.reply_text('Нет записей в таблице email_addresses.')

    except (Exception, Error) as error:
        logger.error(f"Ошибка при получении email-адресов: {error}")
        update.message.reply_text('Произошла ошибка при получении данных.')

    finally:
        if connection:
            cursor.close()
            connection.close()

def get_phone_numbers(update: Update, context):
    connection = None
    try:
        connection = psycopg2.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT,
            database=DB_DATABASE
        )
        cursor = connection.cursor()
        cursor.execute("SELECT phone_number FROM phone_numbers;")
        phone_numbers = cursor.fetchall()

        if phone_numbers:
            phone_list = "\n".join(phone[0] for phone in phone_numbers)
            update.message.reply_text(f'Список номеров телефонов:\n{phone_list}')
        else:
            update.message.reply_text('Нет записей в таблице phone_numbers.')

    except (Exception, Error) as error:
        logger.error(f"Ошибка при получении номеров телефонов: {error}")
        update.message.reply_text('Произошла ошибка при получении данных.')

    finally:
        if connection:
            cursor.close()
            connection.close()


def main():
    updater = Updater(TOKEN, use_context=True)

    dp = updater.dispatcher

    convHandlerVerifyPassword = ConversationHandler(
        entry_points=[CommandHandler('verify_password', verifyPasswordCommand)],
        states={
            'verifyPassword': [MessageHandler(Filters.text & ~Filters.command, verifyPassword)],
        },
        fallbacks=[]
    )
    
    convHandlerFindPhoneNumbers = ConversationHandler(
        entry_points=[CommandHandler('findPhoneNumbers', findPhoneNumbersCommand)],
        states={
            'findPhoneNumbers': [MessageHandler(Filters.text & ~Filters.command, findPhoneNumbers)],
            'savePhoneNumbers': [MessageHandler(Filters.text & ~Filters.command, savePhoneNumbers)],
        },
        fallbacks=[]
    )
    
    convHandlerFindEmail = ConversationHandler(
        entry_points=[CommandHandler('findEmail', findEmailCommand)],
        states={
            'findEmail': [MessageHandler(Filters.text & ~Filters.command, findEmail)],
            'saveEmail': [MessageHandler(Filters.text & ~Filters.command, saveEmail)],
        },
        fallbacks=[]
    )

    convHandlerGetAptList = ConversationHandler(
        entry_points=[CommandHandler('get_apt_list', get_apt_list_command)],
        states={
            'get_apt_list': [MessageHandler(Filters.text & ~Filters.command, get_apt_list)],
        },
        fallbacks=[]
    )

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CommandHandler("help", helpCommand))
    dp.add_handler(convHandlerFindPhoneNumbers)
    dp.add_handler(convHandlerFindEmail)
    dp.add_handler(convHandlerVerifyPassword)

    dp.add_handler(CommandHandler("get_release", get_release))
    dp.add_handler(CommandHandler("get_uname", get_uname))
    dp.add_handler(CommandHandler("get_uptime", get_uptime))
    dp.add_handler(CommandHandler("get_df", get_df))
    dp.add_handler(CommandHandler("get_free", get_free))
    dp.add_handler(CommandHandler("get_mpstat", get_mpstat))
    dp.add_handler(CommandHandler("get_w", get_w))
    dp.add_handler(CommandHandler("get_auths", get_auths))
    dp.add_handler(CommandHandler("get_critical", get_critical))
    dp.add_handler(CommandHandler("get_ps", get_ps))
    dp.add_handler(CommandHandler("get_ss", get_ss))
    dp.add_handler(convHandlerGetAptList)
    dp.add_handler(CommandHandler("get_services", get_services))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, echo))
    dp.add_handler(CommandHandler("get_repl_logs", get_repl_logs))
    dp.add_handler(CommandHandler("get_emails", get_emails))
    dp.add_handler(CommandHandler("get_phone_numbers", get_phone_numbers))

    updater.start_polling()

    updater.idle()

if __name__ == '__main__':
    main()
