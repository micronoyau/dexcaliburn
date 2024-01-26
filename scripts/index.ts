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

    var invokeHistory: {method: string, trace: string}[] = []
    const debounceSend = debounce(() => {
        send({id: "invoke", data: invokeHistory})
        invokeHistory = []
    }, 1000);

    invoke.implementation = function (obj1: Object, obj2: Object[]) {
        log2("Invoked : " + this.toGenericString());
        log("Invoked : " + this.getName());
        let fullMethodName = this.toGenericString() + " || ";
        let stktrc = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());

        invokeHistory.push({method: this.getName(), trace: fullMethodName+stktrc})
        debounceSend()
        return invoke.call(this, obj1, obj2);
    }

}

function sendDynLoadedDexFile() {
    const PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    const init = PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader');

    init.implementation = function (dexPath: string, classLoader) {
        log("Loading " + dexPath);
        log("Using " + String(classLoader));

        send({id:"dex", data: dexPath.split('/').slice(-1)[0] }, readFile(dexPath))
        return init.call(this, dexPath, classLoader);
    }
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
