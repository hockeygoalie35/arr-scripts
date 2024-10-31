import re
import time
from time import sleep
import json
import requests
from dataclasses import dataclass
from requests import Session
from argparse import ArgumentParser
from sys import argv
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, CommandHandler
import logging
import os
from colorama import Fore
from datetime import datetime
import prettylogging

CUSTOM_INIT_PATH = '/custom-cont_init.d/'
CUSTOM_SERVICES_PATH = '/custom-services.d/'
STATUS_FALLBACK_LOCATION = '/custom-services.d/python/ARLStatus.txt'
EXTENDED_CONF_PATH = '/config/extended.conf'
NOT_FOUND_PATH = '/config/extended/logs/notfound'
FAILED_DOWNLOADS_PATH = '/config/extended/logs/downloaded/failed/deezer'
LOG_FILES_DIRECTORY = '/config/logs'
DEBUG_ROOT_PATH = './env'
EXPIRE_MESSAGE = ('---\U0001F6A8WARNING\U0001F6A8-----\nARL TOKEN EXPIRED\n Update arlToken in extended.conf\n'
                  'You can find a new ARL at:\nhttps://rentry.org/firehawk52#deezer-arls')
EXPIRE_COMMANDS = '\n\n\n Other Commands:\n/cancel - Cancel this session\n/disable - Disable Bot'

# Web agent used to access Deezer
USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/110.0'

log_settings = prettylogging.Prettylogger(logger_name='ARLChecker')
log = log_settings.logger


@dataclass
class Plan:
    name: str
    expires: str
    active: bool
    download: bool
    lossless: bool
    explicit: bool


@dataclass
class Account:
    id: int
    token: str
    country: str
    plan: Plan


class AuthError(Exception):
    pass


class ParseError(Exception):
    pass


class ServiceError(Exception):
    pass


class DeezerPlatformProvider:
    NAME = 'Deezer'

    BASE_URL = 'https://www.deezer.com'
    API_PATH = '/ajax/gw-light.php'
    SESSION_DATA = {
        'api_token': 'null',
        'api_version': '1.0',
        'input': '3',
        'method': 'deezer.getUserData'
    }

    def __init__(self):
        super().__init__()
        self.session = Session()
        self.session.headers.update({'User-Agent': USER_AGENT})

    def login(self, username, secret):
        try:
            res = self.session.post(
                self.BASE_URL + self.API_PATH,
                cookies={'arl': secret},
                data=self.SESSION_DATA
            )
            res.raise_for_status()
        except Exception:
            log.error( 'Could not connect! Service down, API changed, wrong credentials or code-related issue.' )
            raise ConnectionError()

        self.session.cookies.clear()

        try:
            res = res.json()
        except Exception:
            log.error( "Could not parse JSON response from DEEZER!" )
            raise ParseError()

        if 'error' in res and res['error']:
            log.error( "Deezer returned the following error:{}".format(res["error"]) )
            raise ServiceError()

        res = res['results']

        if res['USER']['USER_ID'] == 0:
            raise AuthError()

        return Account(username, secret, res['COUNTRY'], Plan(
            res['OFFER_NAME'],
            'Unknown',
            True,
            True,
            res['USER']['OPTIONS']['web_sound_quality']['lossless'],
            res['USER']['EXPLICIT_CONTENT_LEVEL']
        ))
    
    
class LidarrExtendedAPI:
    # sets new token to  extended.conf
    def __init__(self):
        self.root = ''
        self.newARLToken = None
        self.currentARLToken = None
        self.arlLineText = None
        self.arlLineIndex = None
        self.fileText = None
        self.enable_telegram_bot = False
        self.telegram_bot_running = False
        self.telegram_bot_token = None
        self.telegram_user_chat_id = None
        self.telegram_bot_enable_line_text = None
        self.telegram_bot_enable_line_index = None
        self.bot = None
        self.enable_pushover_notify = False
        self.pushover_user_key = None
        self.pushover_app_api_key = None
        self.enable_ntfy_bot = False
        self.ntfy_sever_topic = None
        self.ntfy_user_token = None
        self.ntfy_bot_enable_line_text = None
        self.ntfy_bot_enable_line_index = None

    def parse_extended_conf(self):
        self.currentARLToken = None
        arl_token_match = None
        deezer_active = False
        re_search_pattern = r'"([^"]*)"'
        try:  # Try to open extended.conf and read all text into a var.
            with open(self.root+EXTENDED_CONF_PATH, 'r', encoding='utf-8') as file:
                self.fileText = file.readlines()
                file.close()
        except:
            log.error(f"Could not find {self.root+EXTENDED_CONF_PATH}")
            exit(1)
        # Ensure Deezer is enabled and ARL token is populated
        for line in self.fileText:
            if 'dlClientSource="deezer"' in line or 'dlClientSource="both"' in line:
                deezer_active = True
            if 'arlToken=' in line:
                self.arlLineText = line
                self.arlLineIndex = self.fileText.index(self.arlLineText)
                arl_token_match = re.search(re_search_pattern, line)
                break

        # ARL Token wrong flag error handling.
        if arl_token_match is None:
            log.error("ARL Token not found in extended.conf. Exiting.")
            exit(1)
        elif deezer_active is False:
            log.error("Deezer not set as an active downloader in extended.conf. Exiting.")
            file.close()
            exit(1)
        self.currentARLToken = arl_token_match[0]
        log.success('ARL Found in extended.conf')

        for line in self.fileText:
            if 'telegramBotEnable=' in line:
                self.telegram_bot_enable_line_text = line
                self.telegram_bot_enable_line_index = self.fileText.index(self.telegram_bot_enable_line_text)
                self.enable_telegram_bot = re.search(re_search_pattern, line)[0].replace('"', '').lower() in 'true'
            if 'telegramBotToken=' in line:
                self.telegram_bot_token = re.search(re_search_pattern, line)[0].replace('"', '')
            if 'telegramUserChatID=' in line:
                self.telegram_user_chat_id = re.search(re_search_pattern, line)[0].replace('"', '')
            if 'pushoverEnable=' in line:
                self.enable_pushover_notify = re.search(re_search_pattern, line)[0].replace('"', '').lower() in 'true'
            if 'pushoverUserKey=' in line:
                self.pushover_user_key = re.search(re_search_pattern, line)[0].replace('"', '')
            if 'pushoverAppAPIKey=' in line:
                self.pushover_app_api_key = re.search(re_search_pattern, line)[0].replace('"', '')
            if 'ntfyEnable=' in line:
                if self.enable_telegram_bot is not True:  # doesn't allow multiple bots at the same time
                    self.enable_ntfy_bot = re.search(re_search_pattern, line)[0].replace('"', '').lower() in 'true'
                    self.ntfy_bot_enable_line_text = line
                    self.ntfy_bot_enable_line_index = self.fileText.index(self.ntfy_bot_enable_line_text)
            if 'ntfyServerTopic=' in line:
                self.ntfy_sever_topic = re.search(re_search_pattern, line)[0].replace('"', '')
            if 'ntfyUserToken=' in line:
                self.ntfy_user_token = re.search(re_search_pattern, line)[0].replace('"', '')

        if self.enable_telegram_bot:
            log.success('Telegram bot is enabled.')
            if self.telegram_bot_token is None or self.telegram_user_chat_id is None or self.telegram_bot_token == '' or self.telegram_user_chat_id == '':
                log.error('Telegram bot token or user chat ID not set in extended.conf. Exiting')
                exit(1)
        else:
            log.info('Telegram bot is disabled.')

        # Report Notify/Bot Enable
        if self.enable_pushover_notify:
            log.success('Pushover notify is enabled.')
        else:
            log.info('Pushover notify is disabled.')
        if self.enable_ntfy_bot:
            log.success('ntfy bot is enabled.')
            if self.ntfy_user_token is None or self.ntfy_sever_topic is None or self.ntfy_user_token == '' or self.ntfy_sever_topic == '':
                log.error('NTFY user token or topic not set in extended.conf. Exiting')
                exit(1)
        else:
            log.info('ntfy bot is disabled.')


    def check_token_wrapper(self):  # adds Lidarr_extended specific logging and actions around check_token
        log.info("Checking ARL Token from extended.conf")
        if self.currentARLToken == '""':
            log.info("No ARL Token set in Extended.conf")
            self.report_status("NOT SET")
            exit(0)
        if self.currentARLToken is None:
            log.error('Invalid ARL Token Entry (None Object)')
            return False
        validity_results = check_token(self.currentARLToken)
        if validity_results is True:
            self.report_status('VALID')  # For text fallback method
        else:
            self.report_status('EXPIRED')
            log.error( 'Update the token in extended.conf' )
            if self.telegram_bot_running:  # Don't re-start the telegram bot if it's already running after bot invalid token entry
                return False
            if self.enable_pushover_notify:
                pushover_notify(self.pushover_app_api_key, self.pushover_user_key, EXPIRE_MESSAGE)
            if self.enable_ntfy_bot:
                log.info(f'Starting ntfy bot...Check {self.ntfy_sever_topic} and follow instructions.')
                self.start_ntfy_bot()
            if self.enable_telegram_bot:
                log.info( 'Starting Telegram bot...Check Telegram and follow instructions.' )
                self.telegram_bot_running = True
                self.start_telegram_bot()
            exit(420)

    def set_new_token(self):  # Re-writes extended.conf with previously read-in text, replacing w/ new ARL
        self.fileText[self.arlLineIndex] = self.arlLineText.replace(self.currentARLToken, self.newARLToken)
        with open(self.root+EXTENDED_CONF_PATH, 'w', encoding='utf-8') as file:
            file.writelines(self.fileText)
            file.close()
        log.info("New ARL token written to extended.conf")
        self.parse_extended_conf()

    #  After new token is set, clean up notfound and failed downloads to bypass the default 30 day wait
    def clear_not_found(self):
        paths = [self.root + NOT_FOUND_PATH, self.root+FAILED_DOWNLOADS_PATH]
        for path in paths:
            for file in os.listdir(path):
                file_to_delete = os.path.join(path, file)
                os.remove(file_to_delete)

    def report_status(self, status):
        f = open(self.root+STATUS_FALLBACK_LOCATION, "w")
        now = datetime.strftime(datetime.now(), "%b-%d-%Y at %H:%M:%S")
        f.write(f"{now}: ARL Token is {status}.{' Please update arlToken in extended.conf' if status=='EXPIRED' else ''}")
        f.close()

    def start_telegram_bot(self):
        try:
            self.bot = TelegramBot(self, self.telegram_bot_token, self.telegram_user_chat_id)
        except Exception as e:
            if 'Chat not found' in str(e) or 'Chat_id' in str(e):
                log.error(
                     "Telegram Bot: Chat not found. Check your chat ID in extended.conf, or start a chat with your bot." )
            elif 'The token' in str(e):
                log.error( "Telegram Bot: Check your Bot Token in extended.conf." )
            else:
                log.error('Telegram Bot: ' + str(e))

    def disable_telegram_bot(self):
        compiled = re.compile(re.escape('true'), re.IGNORECASE)
        self.fileText[self.telegram_bot_enable_line_index] = compiled.sub('false', self.telegram_bot_enable_line_text)
        with open(self.root+EXTENDED_CONF_PATH, 'w', encoding='utf-8') as file:
            file.writelines(self.fileText)
            file.close()
        log.info("Telegram Bot Disabled.")

    def start_ntfy_bot(self):
        ntfy_bot = NtfyBot(parent=self, server_plus_topic=self.ntfy_sever_topic, token=self.ntfy_user_token)
        ntfy_bot.ntfy_notify(EXPIRE_MESSAGE + EXPIRE_COMMANDS, expect_response=True)

    def disable_ntfy_bot(self):
        compiled = re.compile(re.escape('true'), re.IGNORECASE)
        self.fileText[self.ntfy_bot_enable_line_index] = compiled.sub('false', self.ntfy_bot_enable_line_text)
        with open(self.root+EXTENDED_CONF_PATH, 'w', encoding='utf-8') as file:
            file.writelines(self.fileText)
            file.close()
        log.info("ntfy Bot Disabled.")


class TelegramBot:
    def __init__(self, parent, telegram_bot_token, telegram_user_chat_id):
        self.parent = parent
        self.telegram_bot_token = telegram_bot_token
        self.telegram_chat_id = telegram_user_chat_id

        # Send initial notification
        async def send_expired_token_notification(application):
            await application.bot.sendMessage(chat_id=self.telegram_chat_id, text=EXPIRE_MESSAGE+EXPIRE_COMMANDS, disable_web_page_preview=True)
            log.info( "Telegram Bot Sent ARL Token Expiry Message " )
            # TODO: Get Chat ID/ test on new bot

        # start bot control
        self.application = ApplicationBuilder().token(self.telegram_bot_token).post_init(send_expired_token_notification).build()
        token_handler = CommandHandler('set_token', self.set_token)
        cancel_handler = CommandHandler('cancel', self.cancel)
        disable_handler = CommandHandler('disable', self.disable_bot)
        self.application.add_handler(token_handler)
        self.application.add_handler(cancel_handler)
        self.application.add_handler(disable_handler)
        self.application.run_polling(allowed_updates=Update.ALL_TYPES)

    async def disable_bot(self, update, context: ContextTypes.DEFAULT_TYPE):
        self.parent.disable_telegram_bot()
        await update.message.reply_text('Disabled Telegram Bot. \U0001F614\nIf you would like to re-enable,\nset telegramBotEnable to true\nin extended.conf')
        log.info( 'Telegram Bot: Send Disable Bot Message :(' )
        self.application.stop_running()

    async def cancel(self, update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text('Canceling...ARLToken is still expired.')
        log.info( 'Telegram Bot: Canceling...ARLToken is still expired.' )
        try:
            self.application.stop_running()
        except Exception:
            pass

    async def set_token(self, update, context: ContextTypes.DEFAULT_TYPE):
        async def send_message(text, reply=False):
            if reply is True:
                await update.message.reply_text(text=text)
            else:
                await context.bot.send_message(chat_id=update.effective_chat.id, text=text)
            log.info("Telegram Bot: " + text )
        try:
            new_token = update.message.text.split('/set_token ')[1]
            if new_token == '':
                raise Exception
        except:
            await update.message.reply_text('Invalid  Entry... Please try again.')
            return
        log.info(f"Telegram Bot:Token received: {new_token}" )
        token_validity = check_token(new_token)
        if token_validity:
            await send_message("ARL valid, applying...")
            self.parent.newARLToken = '"'+new_token+'"'
            self.parent.set_new_token()
            await send_message("Checking configuration...")
            # reparse extended.conf
            self.parent.parse_extended_conf()
            token_validity = check_token(self.parent.currentARLToken)
            if token_validity:
                await send_message("ARL Token Updated! \U0001F44D", reply=True)
                try:
                    self.application.stop_running()
                except Exception:
                    pass

        else:  # If Token invalid
            await send_message("Token expired or invalid. Try another token.", reply=True)
            return


class NtfyBot:
    def __init__(self,parent, server_plus_topic, token, poll_interval=1):
        self.parent = parent
        self.server_plus_topic = server_plus_topic
        self.token = token
        self.command_dict = {"/set_token":self.set_token,"/cancel":self.cancel, "/disable":self.disable_bot}
        self.poll_interval = poll_interval
        self.last_response = ''

    def ntfy_notify(self, message, expect_response=False):  # Send Notification to ntfy topic
        log.info('Attempting ntfy notification')
        try:
            response = requests.post(self.server_plus_topic,
                                     data=message.encode(encoding='utf-8'),
                                     headers={"Authorization": f"Bearer {self.token}"}
                                     )
            if 'http' in json.loads(response.content).keys():
                raise Exception('ntfy notification failed')
            elif 'message' in json.loads(response.content).keys():
                log.success('ntfy notification sent successfully')
        except Exception as e:
            if "Failed to resolve" in str(e):
                log.error("ntfy ERROR: Check if server address is correct")
            elif response.content:
                log.error(
                    f'NTFY Server Response: Code {json.loads(response.content)['http']} - {json.loads(response.content)['error']}')
                log.error('Is server topic set correctly? Is ntfy token correct?')
            else:
                log.error("NTFY ERROR: " + str(e))
            exit(1)
        if expect_response is True:
            sleep(1)
            self.ntfy_listen_for_response()

    def ntfy_listen_for_response(self):
        time.sleep(self.poll_interval) # Prevent cascading "Invalid Command"
        log.info('ntfy bot: Waiting for response...')
        response = None
        while not response:
            sleep(self.poll_interval)
            r = requests.get(f'{self.server_plus_topic}/json?poll=1&since={self.poll_interval}s',
                             headers={"Authorization": f"Bearer {self.token}"})
            for line in r.iter_lines():
                if line:
                    try:
                        log.debug(line.decode('utf-8'))
                        response = json.loads(line.decode('utf-8'))['message']
                    except Exception as e:
                        if json.loads(line.decode('utf-8'))['content']:
                            log.error(f'NTFY Server Response: Code {json.loads(response.content)['http']} - {json.loads(response.content)['error']}')
                            exit(1)
                        else:
                            print(e)
                            exit(1)
            if response:
                log.info(f'user response: {response}')
                self.ntfy_parse_user_response(response)
                break
            log.debug(f'ntfy bot: No valid message received, sleeping for {self.poll_interval} seconds')

    def ntfy_parse_user_response(self,user_response):
        for command in self.command_dict:
            if command in user_response:
                self.last_response = user_response
                self.command_dict[command]()
                return
        self.ntfy_notify('Invalid Command, Try Again.')
        log.error("ntfy Bot - Invalid Command, Try Again.")
        self.ntfy_listen_for_response()

    def cancel(self):
        self.ntfy_notify('Canceling...ARLToken is still expired.')
        log.info('ntfy Bot - Canceling...ARLToken is still expired.')

    def set_token(self):
        try:
            new_token = self.last_response.split('/set_token ')[1]
            if new_token == '':
                raise Exception
        except:
            self.ntfy_notify('Invalid Entry, Try Again.')
            log.error("ntfy Bot - Invalid Entry, Try Again.")
            self.ntfy_listen_for_response()
            return
        log.info(f"ntfy Bot:Token received: {new_token}")
        token_validity = check_token(new_token)
        if token_validity:
            self.ntfy_notify("ARL valid, applying...")
            self.parent.newARLToken = '"' + new_token + '"'
            self.parent.set_new_token()
            self.ntfy_notify("Checking configuration...")
            # reparse extended.conf
            self.parent.parse_extended_conf()
            token_validity = check_token(self.parent.currentARLToken)
            if token_validity:
                self.ntfy_notify("ARL Token Updated! \U0001F44D")
        else:  # If Token invalid
            self.ntfy_notify("Token expired or invalid. Try another token.")
            log.info("ntfy BOT: Token expired or invalid. Try another token.")
            self.ntfy_listen_for_response()


    def disable_bot(self):
        log.info('ntfy Bot: Send Disable Bot Message :(')
        self.ntfy_notify('Disabled ntfy Bot. \U0001F614\nIf you would like to re-enable,\nset nftyEnable to true\nin extended.conf')
        self.parent.disable_ntfy_bot()


def pushover_notify(api_token, user_key, message):  # Send Notification to Pushover
    log.info( 'Attempting Pushover notification' )
    response = requests.post("https://api.pushover.net/1/messages.json", data={
        "token": api_token,
        "user": user_key,
        "message": message
    })
    if response.json()['status'] == 1:
        log.success("Pushover notification sent successfully")
    else:
        for message_error in response.json()['errors']:
            log.error(f"Pushover Response: {message_error}")


def check_token(token=None):
    log.info(f"ARL Token to check: {token}")
    log.info('Checking ARL Token Validity...')
    try:
        deezer_check = DeezerPlatformProvider()
        account = deezer_check.login('', token.replace('"', ''))
        if account.plan:
            log.success( f'Deezer Account Found.' )
            log.info('-------------------------------')
            log.info(f'Plan: {account.plan.name}')
            log.info(f'Expiration: {account.plan.expires}')
            log.info(f'Active: {Fore.GREEN+"Y"+Fore.RESET if account.plan.active else Fore.RED+"N"+Fore.RESET}')
            log.info(f'Download: {Fore.GREEN+"Y"+Fore.RESET if account.plan.download else Fore.RED+"N"+Fore.RESET}')
            log.info(f'Lossless: {Fore.GREEN+"Y"+Fore.RESET if account.plan.lossless else Fore.RED+"N"+Fore.RESET}')
            log.info(f'Explicit: {Fore.GREEN+"Y"+Fore.RESET if account.plan.explicit else Fore.RED+"N"+Fore.RESET}')
            log.info('-------------------------------')
            return True
    except Exception as e:
        if type(e) is AuthError:
            log.error( 'ARL Token Invalid/Expired.' )
            return False
        else:
            log.error(e)
            return


def parse_arguments():
    parser = ArgumentParser(prog='Account Checker', description='Lidarr Extended Deezer ARL Token Tools')
    parser.add_argument('-c', '--check', help='Check if currently set ARL Token is active/valid', required=False, default=False, action='store_true')
    parser.add_argument('-n', '--new_token', help='Set new ARL Token', type=str, required=False, default=False)
    parser.add_argument('-t', '--test_token', help='Test any token for validity', type=str, required=False, default=False)
    parser.add_argument('-d', '--debug', help='For debug and development, sets root path to match testing env. See DEBUG_ROOT_PATH', required=False, default=False, action='store_true')

    if not argv[1:]:
        parser.print_help()
        parser.exit()

    return parser, parser.parse_args()


def get_version(root):
    # Pull script version from bash script. will likely change this to a var passthrough
    try:
        with open(root+CUSTOM_SERVICES_PATH+"ARLChecker", "r") as r:
            for line in r:
                if 'scriptVersion' in line:
                    return re.search(r'"([A-Za-z0-9_./\\-]*)"', line)[0].replace('"', '')
    except Exception as e:
        log.error('Script Version not found! Exiting since script is likely missing')
    exit(1)


def get_active_log(root):
    # Get current log file
    path = root + LOG_FILES_DIRECTORY
    latest_file = max([os.path.join(path, f) for f in os.listdir(path) if 'ARLChecker' in f], key=os.path.getctime)
    return latest_file




def main():
    root = ''
    parser, args = parse_arguments()
    if args.debug is True:  # If debug flag set, works with IDE structure
        root = DEBUG_ROOT_PATH
    # Update log params
    log_settings.version = get_version(root)
    log_settings.log_file = get_active_log(root)
    log_settings.update_format()
    try:
        if args.test_token:
            log.info("CLI Token Tester")
            check_token(args.test_token)
            exit(0)
        arl_checker_instance = LidarrExtendedAPI()
        arl_checker_instance.root = root
        if args.check is True:
            if arl_checker_instance.currentARLToken == '':
                log.error("ARL Token not set. re-run with -n flag")
            arl_checker_instance.parse_extended_conf()
            arl_checker_instance.check_token_wrapper()

        elif args.new_token:
            if args.new_token == '':
                log.error('Please pass new ARL token as an argument')
                exit(96)
            arl_checker_instance.newARLToken = '"'+args.new_token+'"'
            arl_checker_instance.parse_extended_conf()
            arl_checker_instance.set_new_token()

        else:
            parser.print_help()
    except Exception as e:
        logging.error(e, exc_info=True)
        exit(1)


if __name__ == '__main__':
    main()
