import { log, log2, debounce, readFile } from "./utils.js";

export const LOG_LEVEL = 1

var initialClasses: string[] = []
Java.perform(function () {

    // log2PreloadedClasses()
    // log2LoadedClasses()

    // sendDynLoadedDexFile()
    captureInvokeCalls()
    // Interceptor.attach(Module.getExportByName('java.lang.reflect', 'invoke'), {
    //
    let addr: NativePointer = new NativePointer(0)
    Module.load('libart.so').enumerateSymbols().forEach((sym) => {
        if(sym.name.match(new RegExp("method_invoke", 'i'))) {
            log(sym.name + '\t' + sym.type + '\t')
            addr = sym.address
        }
    })


    // Process.enumerateModules().forEach((module) => {
    //     // log(module.name)
    //     module.enumerateExports().forEach((exp) => {
    //         if (exp.name.match("reflect")) {
    //             log(module.name + '\n\t' + exp.name + '\n\t' + exp.type)
    //         }
    //     })
    //     // log(String(Module.getExportByName('libart.so','_ZN3art16WellKnownClasses24java_lang_reflect_MethodE')))
    // })
    Interceptor.attach(addr, {
        onEnter(args) {
            console.log('---------- start')
            console.log('Context information:');
            console.log('Context  : ' + JSON.stringify(this.context));
            console.log('Return   : ' + this.returnAddress);
            console.log('ThreadId : ' + this.threadId);
            console.log('Depth    : ' + this.depth);
            console.log('Errornr  : ' + this.err);
            let s = Thread.backtrace(this.context, Backtracer.ACCURATE)
            log(s.map(DebugSymbol.fromAddress).join('\n') + '\n')
            log(String(s))

            // Save arguments for processing in onLeave.
            // this.fd = args[0].toInt32();
            // this.buf = args[1];
            // this.count = args[2].toInt32();
        },
        onLeave(result) {
            // Show argument 1 (buf), saved during onEnter.
            // const numBytes = result.toInt32();
            // if (numBytes > 0) {
            //     console.log(hexdump(this.buf, { length: numBytes, ansi: true }));
            // }
            console.log('Result   : ' + result);
            console.log('---------- end')
        }
    })
    // captureNewInstaceCalls()
})

// function captureNewInstaceCalls() {
//     const invoke = Java.use('java.lang.class').newInstance.overload("java.lang.Object", "[Ljava.lang.Object;");
//
//     var invokeHistory = new Set<string>();
//     const debounceSend = debounce(() => {
//         let data: {method: string, trace: string}[] = []
//         invokeHistory.forEach((value) => {
//             let arr = value.split('!!')
//             data.push({method: arr[0], trace: arr[1]});
//         });
//         send({id: "invoke", data: data})
//         invokeHistory.clear()
//     }, 1000);
//
//     invoke.implementation = function (obj1: Object, obj2: Object[]) {
//         log2("Invoked : " + this.toGenericString());
//         log("Invoked : " + this.getName());
//         let fullMethodName = this.toGenericString();
//         let stktrc: string = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
//         let call_pos = stktrc.split('\n')[2];
//
//         invokeHistory.add(this.getName() + '!!' + fullMethodName+'\n'+call_pos)
//         debounceSend()
//         return invoke.call(this, obj1, obj2);
//     }
//
// }

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
        log("Invoked : " + String(obj1));
        let s = Thread.backtrace(this.context, Backtracer.ACCURATE)
        log(s.map(DebugSymbol.fromAddress).join('\n') + '\n')
        log(String(s))
        let fullMethodName = this.toGenericString();
        let stktrc: string = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());
        let call_pos = stktrc.split('\n')[2];

        invokeHistory.add(this.getName() + '!!' + fullMethodName+'\n'+call_pos)
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
