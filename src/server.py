import frida
import time
import os
from utils import *
from sys import argv
import json

os.system(f"mkdir -p {OUTPUT_FOLDER}")
script = None
banner = "Welcome to dexcaliburn ! \
To exit, press [enter]"

def error_handler(message):
    """
    Clean logging of errors
    """
    print(message["stack"])

def setup_handler():
    try:
        f = open(HOOK_CONFIG_FILE, 'r')
        script.post({'type': 'hooks', 'payload': f.read()})
    except:
        script.post({'type': 'hooks', 'payload': ''})

def dex_handler(filename, data):
    """
    Write [data] in [filename]
    """
    with open(f'{OUTPUT_FOLDER}/{filename}', 'wb') as f:
        f.write(data)

def rundata_handler(rundata):
    """
    Fetch runtime data from frida
    """
    print("\n### Summary ###\n")
    print(json.dumps(rundata, indent=2))
    with open(argv[2], 'w') as f:
        f.write(json.dumps(rundata, indent=2))

def message_handler(message, data):
    """
    Parse messages from Frida to write dex file / log
    """
    if message["type"] == "error":
        error_handler(message)

    elif message["type"] == "send":
        payload = message["payload"]
        id = payload["id"]
        printd(f"Got message of type: {id}\n")

        if id == "setup":
            setup_handler()
        elif id == "dex":
            dex_handler(payload["filename"], data)
        elif id == "rundata":
            rundata_handler(payload["runData"])


if __name__ == '__main__':
    device = frida.get_usb_device()

    if len(argv) == 3:
        pid = device.spawn([argv[1]])
    else:
        print(f"Usage : {argv[0]} [app] [output json file]")
        exit(-1)

    session = device.attach(pid)

    try:
        f = open(FRIDA_SCRIPT, 'r')

    except FileNotFoundError:
        panic("Unable to find frida script")

    script = session.create_script(f.read())
    script.on("message", message_handler)  # register the message handler
    script.load()
    device.resume(pid)

    print(banner)
    input()
    script.post({'type': 'rundata'})
    input()
