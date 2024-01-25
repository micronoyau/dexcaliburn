import frida
import time
import os

os.system("mkdir -p dex-files")

def dex_handler(file_name, payload):
    with open(f'dex-files/{file_name}', 'wb') as f:
        f.write(payload)

def my_message_handler(message, payload):
    print("python print.", message)
    data = message["payload"]
    if message["type"] == "send":
        id = data["id"]
        if(id == "dex"):
            dex_handler(data["file"], payload)
        elif(id == "other"):
            pass
        else:
            pass
        print (message["payload"])


device = frida.get_usb_device()
pid = device.spawn(["com.example.ut_dyn_load"])
session = device.attach(pid)
with open("out/_script.js") as f:
    script = session.create_script(f.read())
script.on("message", my_message_handler)  # register the message handler
script.load()
device.resume(pid)
time.sleep(5)

