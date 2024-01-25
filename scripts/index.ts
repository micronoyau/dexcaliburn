import { log } from "./logger.js";

function makeid(length: number) {
    let result = '';
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const charactersLength = characters.length;
    let counter = 0;
    while (counter < length) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
        counter += 1;
    }
    return result;
}

function readFile(input_file: string){
    // from dexcalibur
    var fin = Java.use("java.io.FileInputStream").$new(input_file);
    var content = [];
    var b=null;
    var jsBuffer = new Uint8Array(4096);
    var buffer = Java.array('byte', Array.from(jsBuffer));
    do{
        b=fin.read(buffer);
        if(b != -1) {
            for(var i =0; i < b; i++) {
                content.push(buffer[i]);
            }
        }
    }while(b != -1);
    return content;
}

var initialClasses: string[] = []
Java.perform(function () {


    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            initialClasses.push(className);
        },
        onComplete: function () {
            log("Loaded initial classes");
            log(initialClasses.join("\n"));
        }
    });

    const PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    const init = PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader');

    init.implementation = function (dexPath: string, classLoader) {
        // log("Loading " + dexPath);
        // log("Using " + String(classLoader));
        // console.log(dexPath);
        send({id:"dex", file: dexPath.split('/').slice(-1)[0] }, readFile(dexPath))

        return init.call(this, dexPath, classLoader);
    }

    const loadClasser = PathClassLoader.loadClass.overload('java.lang.String');

    loadClasser.implementation = function (loadedClassName: string) {
        log("CLASS" + loadedClassName + "ENDCLASS");
        var loadedClass = Java.use(loadedClassName);
        log(String(loadedClass));
        if (initialClasses.indexOf(loadedClassName) == -1) {
            log(loadedClassName);
            var allClasses = Object.getOwnPropertyNames(loadedClass.__proto__).filter((m => !m.startsWith('$')));
            for (var i in allClasses) {
                log("METHOD" + loadedClassName + "|" + allClasses[i] + "ENDMETHOD");
            }

        }

        return loadClasser.call(this, loadedClassName);
    }
   
    const invoke = Java.use('java.lang.reflect.Method').invoke;
    
    invoke.implementation = function (obj1: Object, obj2: Object[]) {
        log("Invoked : " + this.toGenericString());
        let fullMethodName = this.toGenericString() + " || ";
        let stktrc = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new());

        const ActivityThread = Java.use('android.app.ActivityThread');
        const currentApplication = ActivityThread.currentApplication();
        const context = currentApplication.getApplicationContext();
        const appPath = context.getDataDir().getAbsolutePath();
        const filePath = appPath + "/log-" + makeid(10) + ".txt";
        writeFileSync(filePath, fullMethodName + stktrc);
        log("INVOKE" + filePath + "ENDINVOKE");

        return invoke.call(this, obj1, obj2);
    }

})

