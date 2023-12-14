import io
import subprocess
import re
import os

proc = subprocess.Popen(["frida", "-U", "-f" "com.example.ut_dyn_load", "-l", "out/_script.js"], stdout=subprocess.PIPE)
for line in io.TextIOWrapper(proc.stdout, encoding="utf-8"):  # or another encoding
    path = re.search("(?<=LOADED).*(?=END)", line)
    if path:
        os.system("adb pull " + path.group(0) + " dex-files")
        os.system("adb shell rm " + path.group(0))
