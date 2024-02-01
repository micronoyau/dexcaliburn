from androguard.misc import AnalyzeDex
from androguard.core.analysis.analysis import MethodAnalysis
from smali import SVMType
from sys import argv, exit
from functools import reduce
import re
import os
from const import *
from androguard.util import set_log

set_log("SUCCESS")

DEBUG = False

def panic(msg: str):
    print("PANIC")
    print(msg)
    exit(1)


def printd(msg):
    if DEBUG:
        print(msg)


def canonicalize_svm(meth_name):
    ret = SVMType(meth_name.full_name).pretty_name
    ret = ret.replace(' ', '.', 1)
    i = ret.find(' ')
    ret = ret[:i] + ret[i+1:]
    return ret.replace(' ', ',')


def analyze_log(dex_filename, log_filename, dex_methods, debug=False):
    ret = []

    with open(log_filename, 'r') as f:
        l = f.readline()
        log_fun_name = re.search('[^\s]*\(.*\)', l.strip()).group()

        printd(f"Searching for {log_fun_name}")

        for dex_meth in dex_methods:
            if log_fun_name in dex_meth:
                ret.append((log_fun_name, f.readline().strip()))
                printd(f"Function {log_fun_name} is loaded and present in {dex_filename} !")

    return ret


def read_logs(dex_filename):
    hash, dex, analysis = AnalyzeDex(dex_filename)
    dex_methods = list(map(canonicalize_svm, analysis.get_methods()))

    ret = []
    log_folder = f'{OUTPUT_FOLDER}/{LOG_FOLDER}'
    for log_filename in os.listdir(log_folder):
        ret += analyze_log(dex_filename, log_folder + '/' + log_filename, dex_methods)
    return ret


if __name__ == '__main__':
    if len(argv) != 2:
        panic("Usage : {} [extracted dex file]".format(argv[0]))

    try:
        res = read_logs(argv[1])
        print(f"{len(res)} matches found :")
        print('\n'.join(map(lambda x: x[0] + ' => ' + x[1], res)))

    except FileNotFoundError as e:
        panic(str(e))
