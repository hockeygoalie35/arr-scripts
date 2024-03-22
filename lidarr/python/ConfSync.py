import re, os, logging
from sys import argv, stdout
from colorama import Fore, init
DEBUG_ROOT_PATH = './env'
LOG_FILES_DIRECTORY = '/config/logs'
EXTENDED_CONF_PATH = '/config/extended.conf'
CUSTOM_SERVICES_PATH = '/custom-services.d/'


def init_logging(version, log_file_path):
    # Logging Setup
    logging.basicConfig(
        format=f'%(asctime)s :: ConfSync :: {version} :: %(levelname)s :: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO,
        handlers=[
            logging.StreamHandler(stdout),
            logging.FileHandler(log_file_path, mode="a", encoding='utf-8')
        ]
    )
    logger = logging.getLogger('ARLChecker')

    # Initialize colorama
    init(autoreset=True)
    logger.info(Fore.GREEN + 'Logger initialized'+Fore.LIGHTWHITE_EX)

    return logger


def get_version(root):
    # Pull script version from bash script. will likely change this to a var passthrough
    with open(root+CUSTOM_SERVICES_PATH+"ConfSync", "r") as r:
        for line in r:
            if 'scriptVersion' in line:
                return re.search(r'"([A-Za-z0-9_./\\-]*)"', line)[0].replace('"', '')
    logging.error('Script Version not found! Exiting...')
    exit(1)


def get_active_log(root):
    # Get current log file
    path = root + LOG_FILES_DIRECTORY
    latest_file = max([os.path.join(path, f) for f in os.listdir(path) if 'ConfSync' in f], key=os.path.getctime)
    return latest_file


def read_conf(root):
    log = logging.getLogger('ConfSync')
    try:  # Try to open extended.conf and read all text into a var.
        with open(root+EXTENDED_CONF_PATH, 'r', encoding='utf-8') as file:
            file_text = file.readlines()
            file.close()
    except:
        log.error(f"Could not find {root + EXTENDED_CONF_PATH}")
        exit(1)
    for line in file_text:
        print(line.replace('\n',''))


def main(debug):
    root = ''
    if debug is True:  # If debug flag set, works with IDE structure
        root = DEBUG_ROOT_PATH

    log = init_logging(get_version(root), get_active_log(root))
    log.info("Hello World!")
    read_conf(root)



if __name__ == '__main__':
    main(True)
