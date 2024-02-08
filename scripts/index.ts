import { log, log2, debounce, readFile } from "./utils.js";

export const LOG_LEVEL = 1

var initialClasses: string[] = []
Java.perform(function () {

    // log2PreloadedClasses()
    // log2LoadedClasses()

    sendDynLoadedDexFile()
    captureInvokeCalls()
})

function captureInvokeCalls() {
    const invoke = Java.use('java.lang.reflect.Method').invoke.overload("java.lang.Object", "[Ljava.lang.Object;");

    var invokeHistory = new Set<string>();
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

function sendDynLoadedDexFile() {
    overridePathClassLoader();
    overrideDexClassLoader();
    overrideDelegateLastClassLoader();
    overrideInMemoryClassLoader();
}

function overrideInMemoryClassLoader() {
    const InMemoryClassLoader = Java.use('dalvik.system.InMemoryClassLoader');

    var init = InMemoryClassLoader.$init.overload('[LByteBuffer;' , 'java.lang.String', 'java.lang.ClassLoader');
    init.implementation = function (buffer: any[], _libSearchPath, classLoader) {
        log("Loading from memory");
        log("Using " + String(classLoader));

        send({id:"dex", data: 'memory' }, buffer) // May not work as it's a ByteBuffer array
        return init.call(this, buffer, _libSearchPath, classLoader);
    }

    init = InMemoryClassLoader.$init.overload('ByteBuffer', 'java.lang.ClassLoader');
    init.implementation = function (buffer: any[], classLoader) {
        log("Loading from memory");
        log("Using " + String(classLoader));

        send({id:"dex", data: 'memory' }, buffer)
        return init.call(this, buffer, classLoader);
    }

    init = InMemoryClassLoader.$init.overload('[LByteBuffer;', 'java.lang.ClassLoader');
    init.implementation = function (buffer: any[], classLoader) {
        log("Loading from memory");
        log("Using " + String(classLoader));

        send({id:"dex", data: 'memory' }, buffer)
        return init.call(this, buffer, classLoader);
    }
}

function overrideDexClassLoader() {
    const DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    const init = DexClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.ClassLoader');

    init.implementation = function (dexPath: string, _optiDir, _libSearchPath, classLoader) {
        log("Loading " + dexPath);
        log("Using " + String(classLoader));

        send({id:"dex", data: dexPath.split('/').slice(-1)[0] }, readFile(dexPath))
        return init.call(this, dexPath, _optiDir, _libSearchPath, classLoader);
    }
}

function overridePathClassLoader() {
    const PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    const init = PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader');

    init.implementation = function (dexPath: string, classLoader) {
        log("Loading " + dexPath);
        log("Using " + String(classLoader));

        send({id:"dex", data: dexPath.split('/').slice(-1)[0] }, readFile(dexPath))
        return init.call(this, dexPath, classLoader);
    }
}
// DelegateLastClassLoader(java.lang.String, java.lang.String, java.lang.ClassLoader, boolean)
function overrideDelegateLastClassLoader() {
    const DelegateLastClassLoader = Java.use('dalvik.system.DelegateLastClassLoader');

    var init = DelegateLastClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader');
    init.implementation = function (dexPath: string, classLoader) {
        log("Loading " + dexPath);
        log("Using " + String(classLoader));
        send({id:"dex", data: dexPath.split('/').slice(-1)[0] }, readFile(dexPath))
        return init.call(this, dexPath, classLoader);
    }

    init = DelegateLastClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader');
    init.implementation = function (dexPath: string, _optiPath, classLoader) {
        log("Loading " + dexPath);
        log("Using " + String(classLoader));
        send({id:"dex", data: dexPath.split('/').slice(-1)[0] }, readFile(dexPath))
        return init.call(this, dexPath, _optiPath, classLoader);
    }

    // init = DelegateLastClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader', 'boolean');
    // init.implementation = function (dexPath: string, _optiPath, classLoader, _bool) {
    //     log("Loading " + dexPath);
    //     log("Using " + String(classLoader));
    //     send({id:"dex", data: dexPath.split('/').slice(-1)[0] }, readFile(dexPath))
    //     return init.call(this, dexPath, _optiPath, classLoader, _bool);
    // }
}

function log2LoadedClasses() {
    const PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    const loadClasser = PathClassLoader.loadClass.overload('java.lang.String');

    loadClasser.implementation = function (loadedClassName: string) {
        log2("CLASS" + loadedClassName + "ENDCLASS");
        let loadedClass = Java.ClassFactory.get(this).use(loadedClassName)
        log2(String(loadedClass));
        if (initialClasses.indexOf(loadedClassName) == -1) {
            log2(loadedClassName);
            var allClasses = Object.getOwnPropertyNames(loadedClass.__proto__).filter((m => !m.startsWith('$')));
            for (var i in allClasses) {
                log2("METHOD" + loadedClassName + "|" + allClasses[i] + "ENDMETHOD");
            }
        }

        return loadClasser.call(this, loadedClassName);
    }
}

function log2PreloadedClasses() {
    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            initialClasses.push(className);
        },
        onComplete: function () {
            log2("Loaded initial classes");
            log2(initialClasses.join("\n"));
        }
    });
}
