import json
from pathlib import Path

DEBUG = True
FRIDA_SCRIPT = Path(__file__).parent / "frida-scripts" / "out" / "_script.js"


def panic(msg: str):
    print("PANIC")
    print(msg)
    exit(1)


def printd(msg):
    if DEBUG:
        print(msg)


def dump_json(json_data):
    return json.dumps(json_data, indent=2)
