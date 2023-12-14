import { log } from "./logger.js";
import { createReadStream, createWriteStream } from "./frida-fs.js";
import { Buffer } from "buffer";


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


Java.perform(function () {
    var initialClasses = []

    Java.enumerateLoadedClasses({
        onMatch: function (className) {
            initialClasses.push(className);
        },
        onComplete: function () {
            log("Loaded initial classes");
        }
    });

    const PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    const init = PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader');

    init.implementation = function (dexPath, classLoader) {
        log("Loading " + dexPath);

        var readStream = createReadStream(dexPath)
        var dex_content = ""

        readStream
            .on('readable', function () {
                var chunk;
                while (null !== (chunk = readStream.read())) {
                    dex_content = dex_content.concat(chunk);
                }
            })
            .on('end', function () {
                const ActivityThread = Java.use('android.app.ActivityThread');
                log(String(ActivityThread));
                const currentApplication = ActivityThread.currentApplication();
                const context = currentApplication.getApplicationContext();
                const appPath = context.getDataDir().getAbsolutePath();
                const filePath = appPath + "/" + makeid(10) + ".dex";

                const buf = Buffer.from(dex_content);
                const writeStream = createWriteStream(filePath);
                writeStream.write(buf);
                writeStream.end();

                log("LOADED" + filePath + "END");
            });

        return init.call(this, dexPath, classLoader);
    }
})

