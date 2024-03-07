import frida
import time
import os
from utils import *
from sys import argv

os.system(f"mkdir -p {OUTPUT_FOLDER}")
os.system(f"mkdir -p {LOG_FOLDER}")

script = None

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

def dex_handler(file_name, data):
    """
    Write [data] in [file_name]
    """
    with open(f'{OUTPUT_FOLDER}/{file_name}', 'wb') as f:
        f.write(data)

def invoke_handler(history, data):
    """
    Write log [data] in corresponding log file
    """
    for (idx,data) in enumerate(history):
        with open(f'{LOG_FOLDER}/{data["method"]}-{idx}.txt', 'w') as f:
            f.write(data["trace"])

MESSAGE_TYPES = {
    "setup": setup_handler,
    "dex": dex_handler,
    "invoke": invoke_handler,
}

def message_handler(message, data):
    """
    Parse messages from Frida to write dex file / log
    """
    if message["type"] == "send":
        payload = message["payload"]
        id = payload["id"]
        printd(f"Got message of type: {id}\n")
        if id == "setup":
            setup_handler()
            return
        # Dispatch to correct handler
        for (type, handler) in MESSAGE_TYPES.items():
            if(id == type):
                handler(payload["data"], data)
                break
    elif message["type"] == "error":
        error_handler(message)


if __name__ == '__main__':
    device = frida.get_usb_device()

    if len(argv) == 2:
        pid = device.spawn([argv[1]])
    elif len(argv) == 1:
        pid = device.spawn(["com.example.ut_dyn_load"])
    else:
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

    input()
