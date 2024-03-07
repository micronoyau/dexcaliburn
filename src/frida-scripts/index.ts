/*
 * Frida script. Goals :
 * + Intercept dynamically loaded bytecode and dump it
 * + Intercept reflexive method calls
 * Should be run by server, or manually for debug purposes only.
 */

import { log, log2, debounce, readFile, makeid } from "./utils.js";

export const LOG_LEVEL = 1

var initialClasses: string[] = []
Java.perform(function () {
    sendDynLoadedDexFile()
    captureInvokeCalls()
})

/*
 * Eeach time a reflexive call is attempted, sends a message with the following :
 * + Full method name
 * + Java exception stack trace
 */
function captureInvokeCalls() {
    const invoke = Java.use('java.lang.reflect.Method').invoke.overload("java.lang.Object", "[Ljava.lang.Object;");

    var invokeHistory = new Set<string>();
    // Concatenate time-close messages into a single message
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
        log2("Invoked : " + this.toGenericString());
        log("Invoked : " + this.getName());
        let fullMethodName = this.toGenericString();
        let stktrc: string = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        let call_pos = stktrc.split('\n')[2];

        invokeHistory.add(this.getName() + '!!' + fullMethodName+'\n'+call_pos)
        debounceSend()
        return invoke.call(this, obj1, obj2);
    }
}

/*
 * Eeach time a loader is initialized, sends a message with the loaded bytecode
 */
function sendDynLoadedDexFile() {
    overridePathClassLoader();
    overrideDexClassLoader();
    overrideDelegateLastClassLoader();
    overrideInMemoryDexClassLoader();
}

/*
 * Depending on the current API, some loaders might or might not be available.
 */
function tryOverride(loader: any, loader_prototype: string) {
    try {
        loader();
    } catch(e) {
        log("Unable to override " + loader_prototype);
    }
}

function overrideInMemoryDexClassLoader() {
    const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');

    tryOverride(() => {
        const init = InMemoryDexClassLoader.$init.overload('[java.nio.ByteBuffer;' , 'java.lang.String', 'java.lang.ClassLoader');
        init.implementation = function (buffer: any[], _libSearchPath, classLoader) {
            log("Loading from memory");
            log("Using " + String(classLoader));
            for(let buffer of bufferArray) {
                let len = buffer.remaining();
                let jsBuffer = new Array(len);
                for(let i = 0; i<len; i++) {
                    jsBuffer[i] = buffer.get(i);
                }
                send({id:"dex", data: 'memory-' + makeid(3)}, jsBuffer)
            }
            return init.call(this, buffer, _libSearchPath, classLoader);
        }
    }, "InMemoryDexClassLoader(ByteBuffer[] dexBuffers, String librarySearchPath, ClassLoader parent)");

    tryOverride(() => {
        const init = InMemoryDexClassLoader.$init.overload('[java.nio.ByteBuffer', 'java.lang.ClassLoader');
        init.implementation = function (bufferArray: any[], classLoader) {
            log("Loading from memory");
            log("Using " + String(classLoader));

            for(let buffer of bufferArray) {
                let len = buffer.remaining();
                let jsBuffer = new Array(len);
                for(let i = 0; i<len; i++) {
                    jsBuffer[i] = buffer.get(i);
                }
                send({id:"dex", data: 'memory-' + makeid(3)}, jsBuffer)
            }
            return init.call(this, bufferArray, classLoader);
        }
    }, "InMemoryDexClassLoader(ByteBuffer[] dexBuffers, ClassLoader parent)");

    tryOverride(() => {
        const init = InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader');
        init.implementation = function (buffer, classLoader) {
            log("Loading from memory");
            log("Using " + String(classLoader));

            let len = buffer.remaining();
            let jsBuffer = new Array(len);
            for(let i = 0; i<len; i++) { //very slow for big buffers
                jsBuffer[i] = buffer.get(i);
            }
            send({id:"dex", data: 'memory-' + makeid(3)}, jsBuffer)
            return init.call(this, buffer, classLoader);
        }
    }, "InMemoryDexClassLoader(ByteBuffer dexBuffer, ClassLoader parent)");
}

function overrideDexClassLoader() {
    const DexClassLoader = Java.use('dalvik.system.DexClassLoader');

    tryOverride(() => {
        const init = DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader');

        init.implementation = function (dexPath: string, _optiDir, _libSearchPath, classLoader) {
            log("Loading " + dexPath);
            log("Using " + String(classLoader));

            send({id:"dex", data: dexPath.split('/').slice(-1)[0] }, readFile(dexPath))
            return init.call(this, dexPath, _optiDir, _libSearchPath, classLoader);
        }
    }, "DexClassLoader(String dexPath, String optimizedDirectory, String librarySearchPath, ClassLoader parent)");
}

function overridePathClassLoader() {
    const PathClassLoader = Java.use('dalvik.system.PathClassLoader');

    tryOverride(() => {
        const init = PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader');

        init.implementation = function (dexPath: string, classLoader) {
            log("Loading " + dexPath);
            log("Using " + String(classLoader));

            send({id:"dex", data: dexPath.split('/').slice(-1)[0] }, readFile(dexPath))
            return init.call(this, dexPath, classLoader);
        }
    }, "PathClassLoader(String dexPath, ClassLoader parent)");
}

function overrideDelegateLastClassLoader() {
    const DelegateLastClassLoader = Java.use('dalvik.system.DelegateLastClassLoader');

    tryOverride(() => {
        const init = DelegateLastClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader');
        init.implementation = function (dexPath: string, classLoader) {
            log("Loading " + dexPath);
            log("Using " + String(classLoader));

            send({id:"dex", data: dexPath.split('/').slice(-1)[0] }, readFile(dexPath))
            return init.call(this, dexPath, classLoader);
        }
    }, "DelegateLastClassLoader(String dexPath, ClassLoader parent)");

    tryOverride(() => {
        const init = DelegateLastClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader');
        init.implementation = function (dexPath: string, _optiPath, classLoader) {
            log("Loading " + dexPath);
            log("Using " + String(classLoader));

            send({id:"dex", data: dexPath.split('/').slice(-1)[0] }, readFile(dexPath))
            return init.call(this, dexPath, _optiPath, classLoader);
        }
    }, "DelegateLastClassLoader(String dexPath, String librarySearchPath, ClassLoader parent)");

    tryOverride(() => {
        const init = DelegateLastClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader', 'boolean');
        init.implementation = function (dexPath: string, _optiPath, classLoader, _bool) {
            log("Loading " + dexPath);
            log("Using " + String(classLoader));
            send({id:"dex", data: dexPath.split('/').slice(-1)[0] }, readFile(dexPath))
            return init.call(this, dexPath, _optiPath, classLoader, _bool);
        }
    }, "DelegateLastClassLoader(String dexPath, String librarySearchPath, ClassLoader parent, boolean delegateResourceLoading)");
}
