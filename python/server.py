import io
import subprocess
import re
import os

classNameFile = open("dex-files/classNames.txt","w")
os.system("mkdir -p dex-files")
proc = subprocess.Popen(["frida", "-U", "-f" "com.example.ut_dyn_load", "-l", "out/_script.js"], stdout=subprocess.PIPE)

for line in io.TextIOWrapper(proc.stdout, encoding="utf-8"):  # or another encoding
    pathDexFile = re.search("(?<=LOADEDDEXFILE).*(?=ENDDEXFILE)", line)
    className = re.search("(?<=CLASS).*(?=ENDCLASS)", line)
    invokeName = re.search("(?<=INVOKE).*(?=ENDINVOKE)", line)
    if pathDexFile:
        os.system("adb pull " + pathDexFile.group(0) + " dex-files/")
        os.system("adb shell rm " + pathDexFile.group(0))
    if className:
        classNameFile.write(className.group(0)+"\n")
    if invokeName:
        os.system("adb pull " + invokeName.group(0) + " dex-files/")
        os.system("adb shell rm " + invokeName.group(0))

