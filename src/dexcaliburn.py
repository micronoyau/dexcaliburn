"""
Dexcaliburn : a tool to extract and analyze dynamically loaded android bytecode.
This is the main script :
    + initiates a connection with Frida
    + fetches loaded DEX files
    + outputs a JSON file with reflexive calls xrefs for further analysis
"""

import frida
import os
from utils import *
from sys import argv
import json

os.system(f"mkdir -p {DEX_FOLDER}")
banner = "Welcome to dexcaliburn ! \
To exit, press [enter]"


def error_handler(message):
    """
    Clean logging of errors
    """
    print(message["stack"])


def setup_handler(script):
    """
    Send method names to be hooked once dynamically loaded
    """
    try:
        f = open(HOOK_CONFIG_FILE, 'r')
        script.post({'type': 'hooks', 'payload': f.read()})
    except:
        script.post({'type': 'hooks', 'payload': ''})


def dex_handler(filename, data):
    """
    Write [data] in [filename]
    """
    with open(f'{DEX_FOLDER}/{filename}', 'wb') as f:
        f.write(data)


def rundata_handler(rundata):
    """
    Fetch runtime data from frida, cleans and processes it
    with androguard, and saves it
    """
    with open(argv[2], 'w') as f:
        f.write(json.dumps(rundata, indent=2))


def message_handler(message, data, script):
    """
    Parse messages from Frida and dispatches to matching handler
    """
    if message["type"] == "error":
        error_handler(message)

    elif message["type"] == "send":
        payload = message["payload"]
        id = payload["id"]
        printd(f"Got message of type: {id}\n")

        if id == "setup":
            setup_handler(script)
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

    script_content = ""
    try:
        f = open(FRIDA_SCRIPT, 'r')
        script_content = f.read()
    except FileNotFoundError:
        panic("Unable to find frida script")

    script = session.create_script(script_content)
    script.on("message", lambda message, data: message_handler(message,data,script))
    script.load()
    device.resume(pid)

    print(banner)
    input()
    script.post({'type': 'rundata'})
    input()
