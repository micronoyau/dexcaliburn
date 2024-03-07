let myvar = 0;

Java.perform(() => {
    const PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    const loadClass = PathClassLoader.loadClass.overload('java.lang.String');

    console.log(PathClassLoader);

    loadClass.implementation = function (className) {
        console.log('Beginning of loadClass : ', className);
        let ret = loadClass.call(this, className);
        myvar = ret;

        // Java.classFactory.loader = PathClassLoader;

        console.log('ccccccccccccccccccccccccccccccccccccccccccc');
        console.log(ret.getClass());
        console.log('ccccccccccccccccccccccccccccccccccccccccccc');

        console.log('After loadClass base implem : ', className);
        let methods = ret.getDeclaredMethods();
        console.log('*** className = ', className, ' ****\n', methods[0]);

        if (className == 'com.example.ut_dyn_load.SmsReceiver') {
            console.log(Java.enumerateClassLoadersSync());
            var classLoaderToUse = Java.enumerateClassLoadersSync()[3];
            console.log(classLoaderToUse);

            // Java.classFactory.loader = classLoaderToUse; //Set the classloader to the correct one

            let classFactory = Java.ClassFactory.get(classLoaderToUse);

            // Java.classFactory.loader = PathClassLoader;
            console.log('SmsReceiver found ? ', classLoaderToUse.findClass('com.example.ut_dyn_load.SmsReceiver'));

            // const clazz = classLoaderToUse.use(className)
            const clazz = classFactory.use(className)

            console.log('__________________________', classFactory)
            console.log(clazz)
            console.log(clazz.a)

            // const clazz = Java.use(className)
            clazz.a.overload('android.content.Context', 'android.content.BroadcastReceiver').implementation = function (context, receiver) {
                let ret = clazz.a.call(this, context, receiver);
                console.log("===================== mateo est ma bitch");
                return ret;
            }

            // console.log(Java.use(className));

            console.log('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
            Java.enumerateLoadedClasses({
                onMatch: function(cname) {
                    // console.log(cname);
                    if (cname == className) {
                        console.log('sharu est ma bitch');
                        // console.log(Java.ClassFactory.get(PathClassLoader).use(cname));
                        // console.log(Java.use(cname));
                    }
                },
                onComplete: function() {}
            });
            // console.log(ret.class.cannotCastMsg)
            console.log(ret)
            console.log('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');

            methods.forEach((meth) => {
                console.log(meth);
            });
            // methods[0].overload('android.content.Context', 'android.content.BroadcastReceiver').implementation = function (context, receiver) {
            //     console.log('a is called heya');
            //     return methods[0].call(this, context, receiver);
            // }
        }

        return ret;
    }

})
