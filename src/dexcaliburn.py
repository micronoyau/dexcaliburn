"""
Dexcaliburn : a tool to extract and analyze dynamically loaded android bytecode.
This is the main script :
    + initiates a connection with Frida
    + fetches loaded DEX files
    + outputs a JSON file with reflexive calls xrefs for further analysis
"""

from enum import Enum
from androguard.core.androconf import sys
from androguard.misc import AnalyzeDex, re
from androguard.util import set_log
import frida
import os
from utils import *
import json
import argparse

os.system(f"mkdir -p {DEX_FOLDER}")
banner = "Welcome to dexcaliburn ! \
To exit, press [enter]"

# Disable androguard logs
set_log("SUCCESS")


def filter_xrefs(rundata):
    print("Filtering xrefs ...")
    xrefs = []

    for dex_filename in rundata['dexFiles']:
        dex_path = f'{DEX_FOLDER}/{dex_filename}'
        hash, dex, analysis = AnalyzeDex(dex_path)
        getclassname = lambda m: m.class_name.replace('/','.')[1:-1]

        for xref in rundata['xrefs']:
            dex_methods = list( \
                        filter(lambda m: getclassname(m) == xref['method']['className'], \
                        filter(lambda m: m.name == xref['method']['methodName'], \
                        filter(lambda m: not m.is_external(), analysis.get_methods()))))
            # This function is a match
            if len(dex_methods) != 0:
                xref['dexFile'] = dex_filename
                xrefs.append(xref)

    rundata['xrefs'] = xrefs
    return rundata


def filter_xrefs_files(input, output):
    with open(input, 'r') as f:
        with open(output, 'w') as out:
            rundata = filter_xrefs(json.loads(f.read()))
            rundata_filtered = dump_json(rundata)
            out.write(rundata_filtered)
            print(f"Filtered output (saved to {output}):")
            print(rundata_filtered)


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


def rundata_handler(rundata, out):
    """
    Cleans and process runtime data from frida, then saves it
    """
    print(f"===== Unfiltered output (saved in {out}) =====")
    rundata_str = dump_json(rundata)
    print(rundata_str)

    with open(out, 'w') as f:
        f.write(rundata_str)

    # print("\n\n*** Press enter again to exit ***")
    print("Press \'f\' to filter output")


def message_handler(message, data, args):
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
            setup_handler(args['script'])
        elif id == "dex":
            dex_handler(payload["filename"], data)
        elif id == "rundata":
            rundata_handler(payload["runData"], args["output"])

class Action(Enum):
    RUN = 'run'
    FILTER = 'filter'

    def __eq__(self, b):
        return self.value == b

if __name__ == '__main__':
    device = frida.get_usb_device()

    parser = argparse.ArgumentParser(
                        prog='Dexcaliburn',
                        description='''
Dexcaliburn : a tool to extract and analyze dynamically loaded android bytecode.
This is the main script :
    + initiates a connection with Frida
    + fetches loaded DEX files
    + outputs a JSON file with reflexive calls xrefs for further analysis
                        ''')

    parser.add_argument('-o',
                        '--output',
                        help='Output JSON file')
    parser.add_argument('-i',
                        '--input',
                        help='Input JSON file')
    parser.add_argument('-a',
                        '--app',
                        help='Target application')
    parser.add_argument('action',
                        choices=['run', 'filter'],
                        nargs=1,
                        help='Action to perform')

    args = parser.parse_args()

    if args.action[0] == Action.RUN:
        if not args.app or not args.output:
            print("You need to provide a target application and an output file")
            sys.exit(-1)

        pid = device.spawn([args.app])
        session = device.attach(pid)

        script_content = ""
        try:
            f = open(FRIDA_SCRIPT, 'r')
            script_content = f.read()
        except FileNotFoundError:
            panic("Unable to find frida script")

        script = session.create_script(script_content)
        script.on("message",
                  lambda message, data: message_handler(message,
                                                        data,
                                                        {'script': script,
                                                         'output': args.output}))
        script.load()
        device.resume(pid)

        print(banner)
        input()
        script.post({'type': 'rundata'})

        tofilter = input()
        if tofilter == 'f':
            ext_pos = re.search('\\.[^\\.]*$', args.output)
            if not ext_pos:
                panic("Parse error")
            ext_pos = ext_pos.start()
            filtered_name = args.output[:ext_pos] + '-filtered' + args.output[ext_pos:]
            filter_xrefs_files(args.output, filtered_name)

        script.unload()

    elif args.action[0] == Action.FILTER:
        if not args.input or not args.output:
            print("You need to provide input and output files")
            sys.exit(-1)

        filter_xrefs_files(args.input, args.output)
