from androguard.misc import AnalyzeDex
from androguard.core.analysis.analysis import MethodAnalysis
import re
from sys import argv, exit
from functools import reduce

def panic(msg: str):
    print("PANIC")
    print(msg)
    exit(1)

def canonicalize(m: MethodAnalysis):
    ret = ""
    ret += m.access
    ret += m.get_class_name().replace('/', '.')[1:-1]
    # ret +=
    m.full_name

def analyze_log(classes, log_filename):
    with open(log_filename, 'r') as f:
        c = '.'.join(f.readline().split(' ||')[0].split(' ')[-1].split('(')[0].split('.')[:-1]);
        if c in classes:
            print("Androguard found dynamically-loaded method {} invoked in {}".format(c, log_filename))

if __name__ == '__main__':
    if len(argv) != 3:
        panic("Usage : {} [extracted dex file] [invoked function log]".format(argv[0]))

    try:
        hash, dex, analysis = AnalyzeDex(argv[1])
        classes = list(map(lambda c: c.name[1:-1].replace('/','.'), analysis.get_internal_classes()))
        analyze_log(classes, argv[2])

    except FileNotFoundError as e:
        panic(str(e))
