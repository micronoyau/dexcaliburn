import sys
import frida

device = frida.get_device_manager().enumerate_devices()[-1]
pid = device.spawn(["com.example.ut_dyn_load"])
session = device.attach(pid)
file = open("out/_script.js", 'r')
ss = file.read()

script = session.create_script(ss)
script.load()
device.resume(pid)


sys.stdin.read()
session.detach()
