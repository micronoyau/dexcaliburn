DEBUG = True
OUTPUT_FOLDER = 'dex-files'
LOG_FOLDER = 'logs'
FRIDA_SCRIPT = 'src/frida-scripts/out/_script.js'

def panic(msg: str):
    print("PANIC")
    print(msg)
    exit(1)

def printd(msg):
    if DEBUG:
        print(msg)
