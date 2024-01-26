import frida
import time
import os

OUTPUT_FOLDER = 'dex-files'

os.system("mkdir -p " + OUTPUT_FOLDER)

def dex_handler(file_name, data):
    with open(f'{OUTPUT_FOLDER}/{file_name}', 'wb') as f:
        f.write(data)

def invoke_handler(history, data):
    for (idx,data) in enumerate(history):
        with open(f'{OUTPUT_FOLDER}/log-{data["method"]}-{idx}.txt', 'w') as f:
            f.write(data["trace"])

MESSAGE_TYPES = {
    "dex": dex_handler,
    "invoke": invoke_handler,
}

def my_message_handler(message, data):
    payload = message["payload"]
    if message["type"] == "send":
        id = payload["id"]
        print(f"Got message of type: {id}")
        for (type, handler) in MESSAGE_TYPES.items():
            if(id == type):
                handler(payload["data"], data)
                break


device = frida.get_usb_device()
pid = device.spawn(["com.example.ut_dyn_load"])
session = device.attach(pid)
with open("out/_script.js") as f:
    script = session.create_script(f.read())
script.on("message", my_message_handler)  # register the message handler
script.load()
device.resume(pid)
time.sleep(5)

