# Use this script after frida instrumentation
# to see where dynamically loaded methods are called

from androguard.misc import AnalyzeDex
from androguard.core.analysis.analysis import MethodAnalysis
from smali import SVMType
from sys import argv, exit
from functools import reduce
import re
import os
from utils import *
from androguard.util import set_log

# Disable androguard logs
set_log("SUCCESS")


def format_meth_name(meth):
    """
    Format method [meth] to pretty names (log-compatible)
    """
    ret = SVMType(meth.full_name).pretty_name
    ret = ret.replace(' ', '.', 1)
    i = ret.find(' ')
    ret = ret[:i] + ret[i+1:]
    return ret.replace(' ', ',')


def log_matches(dex_filename, log_filename, dex_methods, debug=False):
    """
    Search if the reflexivity-invoked method name in error trace [log_filename]
    is present in [dex_filename]. [dex_method] : androguard methods extracted
    from [dex_filename].
    """
    ret = [] # Array of (found method name, invoke location)

    with open(log_filename, 'r') as f:
        l = f.readline()

        # Keep only method name and argument types
        log_fun_name = re.search('[^\s]*\(.*\)', l.strip()).group()
        printd(f"Searching for {log_fun_name}")

        for dex_meth in dex_methods:
            if log_fun_name in dex_meth:
                ret.append((log_fun_name, f.readline().strip()))
                printd(f"Function {log_fun_name} is loaded and present in {dex_filename} !")

    return ret


def search_logs(dex_filename):
    """
    Search in all reflexivity invokes logs if a call matches a
    method present in [dex_filename]
    """
    hash, dex, analysis = AnalyzeDex(dex_filename)
    dex_methods = list(map(format_meth_name, analysis.get_methods()))

    ret = [] # Array of (found method name, invoke location)
    for log_filename in os.listdir(LOG_FOLDER):
        ret += log_matches(dex_filename, f'{LOG_FOLDER}/{log_filename}', dex_methods)
    return ret


if __name__ == '__main__':
    if len(argv) != 2:
        panic("Usage : {} [extracted dex file]".format(argv[0]))

    try:
        res = search_logs(argv[1])
        print(f"{len(res)} matches found :")
        print('\n'.join(map(lambda x: x[0] + ' => ' + x[1], res)))

    except FileNotFoundError as e:
        panic(str(e))
