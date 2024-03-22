/*
 * Frida script. Goals :
 * + Intercept dynamically loaded bytecode and dump it
 * + Intercept reflexive method calls
 * Should be run by server, or manually for debug purposes only.
 */

import { log, log2, readFile, makeid } from "./utils.js";

export const LOG_LEVEL = 1

enum LocationSource {
    DEBUG = 'debug',
    BINARY = 'binary'
};

// Data gathered during runtime
let runData: {
    dexFiles: string[],
    xrefs: {
        method: string
        location: {
            calling_method: string,
            position: number,
            source: LocationSource
        },
        count: number
    }[]
} = { dexFiles: [], xrefs: [] };

// Key : class name, value : methods to be dynamically hooked
let hookedMethods: { [key: string]: string[] } = {}

Java.perform(function() {
    fetchHookConfig();
    setupExitHandler();
    overrideloadClassForDynHooking();
    overrideClassLoaderInit();
    captureInvokeCalls();
})

/*
 * Receives a list of methods to be dynamically hooked
 */
function fetchHookConfig() {
    send({ id: "setup" });
    recv('hooks', (val) => {
        if (val.payload == '') return;
        val.payload.trim().split('\n').forEach((line: string) => {
            let className = line.split('.').slice(0, -1).join('.');
            let methodName = line.split('.').slice(-1)[0];
            if (className in hookedMethods) {
                hookedMethods[className].push(methodName);
            } else {
                hookedMethods[className] = [methodName];
            }
        });
    }).wait();
}

/*
 * Sets up the handler to send all data upon quitting
 */
function setupExitHandler() {
    recv('rundata', (_) => {
        send({ id: "rundata", runData: runData });
    });
}

function overrideloadClassForDynHooking() {
    for (let classLoaderName of ['InMemoryDexClassLoader', 'DexClassLoader', 'PathClassLoader', 'DelegateLastClassLoader']) {
        const classLoader = Java.use('dalvik.system.' + classLoaderName);
        tryOverride(() => {
            const loadClass = classLoader.loadClass.overload('java.lang.String');
            loadClass.implementation = function(className: string) {
                let ret = loadClass.call(this, className);
                if (className in hookedMethods) {
                    hookedMethods[className].forEach((methodName: string) => {
                        hookDynamicMethod(className, methodName);
                    });
                }
                return ret;
            }
        }, `${classLoaderName}.loadClass(String className)`);
    }
}

/*
 * Each time a reflexive call is attempted, stores the following :
 * + Full method name
 * + Java exception stack trace
 */
function captureInvokeCalls() {
    const invoke = Java.use('java.lang.reflect.Method').invoke.overload("java.lang.Object", "[Ljava.lang.Object;");

    invoke.implementation = function(obj1: Object, obj2: Object[]) {
        log2("Invoked : " + this.getName());
        let method = this.toGenericString();
        let stacktrace: string = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        let raw_location = stacktrace.split('\n')[2];

        // Parse raw location
        let calling_method = raw_location.match(/(?<=\tat\s).*(?=\()/)?.[0];
        if (!calling_method) calling_method = '';
        let source = raw_location.match(/(?<=\().*(?=:)/)?.[0] === 'Unknown Source'
            ? LocationSource.BINARY
            : LocationSource.DEBUG;
        let position_ = raw_location.match(/(?<=:).*(?=\))/)?.[0];
        let position = (position_ ? Number(position_) : 0);

        // JS does not allow tuple-indexed dictionaries, this is an non-optimal way around
        let xref_index = runData.xrefs.findIndex(xref => (xref.method == method)
            && (xref.location.calling_method == calling_method)
            && (xref.location.source == source)
            && (xref.location.position == position));
        if (xref_index == -1) {
            runData.xrefs.push({
                method: method,
                location: {
                    calling_method: calling_method,
                    position: position,
                    source: source
                },
                count: 1
            });
        } else {
            runData.xrefs[xref_index].count += 1;
        }

        return invoke.call(this, obj1, obj2);
    }
}

/*
 * Basic hook for dynamically loaded methods : dump arguments
 */
function hookDynamicMethod(className: string, methodName: string) {
    Java.enumerateClassLoadersSync().forEach((loader) => {
        try {
            let clazz = Java.ClassFactory.get(loader).use(className);
            let method = clazz[methodName];
            method.overloads.forEach((overload: any) => {
                overload.implementation = function(...args: any) {
                    console.log("Called : " + methodName + "(" + overload.argumentTypes.map((elem: any) => elem.className).join(', ') + ")");
                    console.log("Args : ", args);
                    return overload.call(this, ...args);
                };
            });
        } catch (e) {
        }
    });
}

/*
 * Depending on the current API, some loaders might or might not be available.
 */
function tryOverride(loader: any, loader_prototype: string) {
    try {
        loader();
    } catch (e) {
        log2("Unable to override " + loader_prototype);
    }
}

/*
 * Return a default implementation for a memory dependent classLoader init method
 */
function memoryClassLoaderHookSetup(is_array: boolean) {
    return function(init_method: Java.Method<{}>) {
        return function(this: any, ...args: any[]) {
            log("Loading new dex from memory buffer");
            let bufferArray = args[0];
            if (!is_array) {
                bufferArray = [bufferArray]
            }

            for (let buffer of bufferArray) {
                // https://github.com/frida/frida/issues/1281
                var jsonString = Java.use('org.json.JSONArray').$new(buffer.array()).toString();
                var jsBuffer = JSON.parse(jsonString);
                let filename = 'memory-' + makeid(3);
                log(`Sending dex as '${filename}'`)
                send({ id: "dex", filename: filename }, jsBuffer)
                runData.dexFiles.push(filename);
            }
            return init_method.call(this, ...args);
        }
    }
}

/*
 * Return a default implementation for a file dependent classLoader init method
 */
function fileClassLoaderHook(init_method: Java.Method<{}>) {
    return function(this: any, ...args: any[]) {
        let dexPath = args[0];
        log("Loading new dex from file: " + dexPath);
        let filename = dexPath.split('/').slice(-1)[0]
        log(`Sending dex as '${filename}'`)
        send({ id: "dex", filename: filename }, readFile(dexPath))
        runData.dexFiles.push(filename);
        return init_method.call(this, ...args);
    }
}

/*
 * Each time a loader is initialized, sends a message with the loaded bytecode
 */
function overrideClassLoaderInit() {
    const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
    const DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    const PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    const DelegateLastClassLoader = Java.use('dalvik.system.DelegateLastClassLoader');

    const registry = [
        {
            classLoader: InMemoryDexClassLoader, argsList: ['[java.nio.ByteBuffer;', 'java.lang.String', 'java.lang.ClassLoader'],
            hook: memoryClassLoaderHookSetup(true), debugString: "InMemoryDexClassLoader(ByteBuffer[] dexBuffers, String librarySearchPath, ClassLoader parent)"
        },
        {
            classLoader: InMemoryDexClassLoader, argsList: ['[java.nio.ByteBuffer', 'java.lang.ClassLoader'],
            hook: memoryClassLoaderHookSetup(true), debugString: "InMemoryDexClassLoader(ByteBuffer[] dexBuffers, ClassLoader parent)"
        },
        {
            classLoader: InMemoryDexClassLoader, argsList: ['java.nio.ByteBuffer', 'java.lang.ClassLoader'],
            hook: memoryClassLoaderHookSetup(false), debugString: "InMemoryDexClassLoader(ByteBuffer dexBuffer, ClassLoader parent)"
        },
        {
            classLoader: DexClassLoader, argsList: ['java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'],
            hook: fileClassLoaderHook, debugString: "DexClassLoader(String dexPath, String optimizedDirectory, String librarySearchPath, ClassLoader parent)"
        },
        {
            classLoader: PathClassLoader, argsList: ['java.lang.String', 'java.lang.ClassLoader'],
            hook: fileClassLoaderHook, debugString: "PathClassLoader(String dexPath, ClassLoader parent)"
        },
        {
            classLoader: DelegateLastClassLoader, argsList: ['java.lang.String', 'java.lang.ClassLoader'],
            hook: fileClassLoaderHook, debugString: "DelegateLastClassLoader(String dexPath, ClassLoader parent)"
        },
        {
            classLoader: DelegateLastClassLoader, argsList: ['java.lang.String', 'java.lang.String', 'java.lang.ClassLoader'],
            hook: fileClassLoaderHook, debugString: "DelegateLastClassLoader(String dexPath, String librarySearchPath, ClassLoader parent)"
        },
        {
            classLoader: DelegateLastClassLoader, argsList: ['java.lang.String', 'java.lang.String', 'java.lang.ClassLoader', 'boolean'],
            hook: fileClassLoaderHook, debugString: "DelegateLastClassLoader(String dexPath, String librarySearchPath, ClassLoader parent, boolean delegateResourceLoading)"
        },
    ];

    for (let entry of registry) {
        tryOverride(() => {
            const init = entry.classLoader.$init.overload(...entry.argsList);
            init.implementation = entry.hook(init);
        }, entry.debugString);
    }
}
