/*
 * Frida script. Goals :
 * + Intercept dynamically loaded bytecode and dump it
 * + Intercept reflexive method calls
 * Should be run by server, or manually for debug purposes only.
 */

import { log, log2, debounce, readFile, makeid } from "./utils.js";

export const LOG_LEVEL = 1

let hookedMethods: { [key: string]: string[] } = {}

Java.perform(function () {
    fetchHookConfig()
    overrideloadClassForDynHooking();
    overrideClassLoaderInit();
    captureInvokeCalls()
})

/**
 * Each time a reflexive call is attempted, sends a message with the following :
 * + Full method name
 * + Java exception stack trace
 */
function captureInvokeCalls() {
    const invoke = Java.use('java.lang.reflect.Method').invoke.overload("java.lang.Object", "[Ljava.lang.Object;");

    var invokeHistory = new Set<string>();
    // Concatenate invoke messages into a single message to avoid flooding
    const debounceSend = debounce(() => {
        let data: {method: string, trace: string}[] = []
        invokeHistory.forEach((value) => {
            let arr = value.split('!!')
            data.push({method: arr[0], trace: arr[1]});
        });
        send({id: "invoke", data: data})
        invokeHistory.clear()
    }, 1000);

    invoke.implementation = function (obj1: Object, obj2: Object[]) {
        log2("Invoked : " + this.getName());
        let fullMethodName = this.toGenericString();
        let stktrc: string = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        let call_pos = stktrc.split('\n')[2];

        invokeHistory.add(this.getName() + '!!' + fullMethodName+'\n'+call_pos)
        debounceSend()
        return invoke.call(this, obj1, obj2);
    }
}

function fetchHookConfig() {
    send({id: "setup"});
    recv('hooks', (val) => {
        if (val.payload == '') return;
        val.payload.trim().split('\n').forEach( (line: string) => {
            let className = line.split('.').slice(0,-1).join('.');
            let methodName = line.split('.').slice(-1)[0];

            if (className in hookedMethods) {
                hookedMethods[className].push(methodName);
            } else {
                hookedMethods[className] = [methodName];
            }
        });
    }).wait();
}

/**
 * Basic hook for dynamically loaded methods : dump arguments
 */
function hookDynamicMethod(className: string, methodName: string) {
    let success = false;

    Java.enumerateClassLoadersSync().forEach( (loader) => {
        try {
            let clazz = Java.ClassFactory.get(loader).use(className);
            let method = clazz[methodName];
            method.overloads.forEach( (overload: any) => {
                overload.implementation = function(...args: any) {
                    console.log("Called : " + methodName + "(" + overload.argumentTypes.map( (elem: any)=>elem.className).join(', ') + ")");
                    console.log("Args : ", args);
                    return overload.call(this, ...args);
                };
            });
        } catch(e) {
        }
    });

    return success;
}

/**
 * Depending on the current API, some loaders might or might not be available.
 */
function tryOverride(loader: any, loader_prototype: string) {
    try {
        loader();
    } catch(e) {
        log2("Unable to override " + loader_prototype);
    }
}

function memoryClassLoaderHookSetup(is_array: boolean) {
    return function (init_method: Java.Method<{}>) {
        return function (this: any, ...args: any[]) {
            log("Loading new dex from memory buffer");
            let bufferArray = args[0];
            if(!is_array) {
                bufferArray = [bufferArray]
            }

            for(let buffer of bufferArray) {
                let len = buffer.remaining();
                let jsBuffer = new Array(len);
                for(let i = 0; i<len; i++) {
                    jsBuffer[i] = buffer.get(i);
                }
                let file_name = 'memory-' + makeid(3);
                log(`Sending dex as '${file_name}'`)
                send({id:"dex", data: file_name}, jsBuffer)
            }
            return init_method.call(this, ...args);
        }
    }
}

/**
 * Return a default implementation for a file dependent classLoader init method
 */
function fileClassLoaderHook(init_method: Java.Method<{}>) {
    return function (this: any, ...args: any[]) {
        let dexPath = args[0];
        log("Loading new dex from file: " + dexPath);
        let file_name = dexPath.split('/').slice(-1)[0]
        log(`Sending dex as '${file_name}'`)
        send({id:"dex", data: file_name}, readFile(dexPath))
        return init_method.call(this, ...args);
    }
}

/**
 * Each time a loader is initialized, sends a message with the loaded bytecode
 */
function overrideClassLoaderInit() {
    const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
    const DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    const PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    const DelegateLastClassLoader = Java.use('dalvik.system.DelegateLastClassLoader');

    const registry = [
        {classLoader: InMemoryDexClassLoader, argsList: ['[java.nio.ByteBuffer;' , 'java.lang.String', 'java.lang.ClassLoader'],
            hook: memoryClassLoaderHookSetup(true), debugString: "InMemoryDexClassLoader(ByteBuffer[] dexBuffers, String librarySearchPath, ClassLoader parent)"},
        {classLoader: InMemoryDexClassLoader, argsList: ['[java.nio.ByteBuffer', 'java.lang.ClassLoader'],
            hook: memoryClassLoaderHookSetup(true), debugString: "InMemoryDexClassLoader(ByteBuffer[] dexBuffers, ClassLoader parent)"},
        {classLoader: InMemoryDexClassLoader, argsList: ['java.nio.ByteBuffer', 'java.lang.ClassLoader'],
            hook: memoryClassLoaderHookSetup(false), debugString: "InMemoryDexClassLoader(ByteBuffer[] dexBuffers, ClassLoader parent)"},
        {classLoader: DexClassLoader, argsList: ['java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'],
            hook: fileClassLoaderHook, debugString: "DexClassLoader(String dexPath, String optimizedDirectory, String librarySearchPath, ClassLoader parent)"},
        {classLoader: PathClassLoader, argsList: ['java.lang.String', 'java.lang.ClassLoader'],
            hook: fileClassLoaderHook, debugString: "PathClassLoader(String dexPath, ClassLoader parent)"},
        {classLoader: DelegateLastClassLoader, argsList: ['java.lang.String', 'java.lang.ClassLoader'],
            hook: fileClassLoaderHook, debugString: "DelegateLastClassLoader(String dexPath, ClassLoader parent)"},
        {classLoader: DelegateLastClassLoader, argsList: ['java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'],
            hook: fileClassLoaderHook, debugString: "DelegateLastClassLoader(String dexPath, String librarySearchPath, ClassLoader parent)"},
        {classLoader: DelegateLastClassLoader, argsList: ['java.lang.String', 'java.lang.String', 'java.lang.ClassLoader', 'boolean'],
            hook: fileClassLoaderHook, debugString: "DelegateLastClassLoader(String dexPath, String librarySearchPath, ClassLoader parent, boolean delegateResourceLoading)"},
    ];

    for(let entry of registry) {
        tryOverride(() => {
            const init = entry.classLoader.$init.overload(...entry.argsList);
            init.implementation = entry.hook(init);
        }, entry.debugString);
    }
}

function overrideloadClassForDynHooking() {
    for(let classLoaderName of ['InMemoryDexClassLoader', 'DexClassLoader', 'PathClassLoader', 'DelegateLastClassLoader']) {
        const classLoader = Java.use('dalvik.system.' + classLoaderName);
        tryOverride(() => {
            const loadClass = classLoader.loadClass.overload('java.lang.String');
            loadClass.implementation = function (className: string) {
                let ret = loadClass.call(this, className);
                if (className in hookedMethods) {
                    hookedMethods[className].forEach( (methodName: string) => {
                        hookDynamicMethod(className, methodName);
                    });
                }
                return ret;
            }
        }, `${classLoaderName}.loadClass(String className)`);
    }
}
