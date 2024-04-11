# Wiki

This markdown regroup all the issues and solutions we found during the project, as well as detailing the process to detect each `ClassLoader`.

## Frida Script Overview

The script does a few things at startup:

1. Fetching the hooks config, see [below](#hooking-dynamically-loaded-method).

    Communicate with the python serveur to initialize the `hookedMethods` array.

2. Override loadClass for dynamic hooking

    Setup hooks on `loadClass` method of commun ClassLoader to provide a way to hook method
    not present in the JVM at the start. It uses the `hookdedMethods` array.

3. Override ClassLoader init method

    Setup hooks on many ClassLoader to detect and extract the dex content.

4. Capture invoke calls.

    Once the new class is loaded, it is often run via the `Method.invoke` method. In order to detect such calls, we hook this method and log all the method that are run that way.
    The result of this will be later analysed with AndroGuard.

5. Setup exit handler

    Setup a `recv` hook to receive the exit signal from the python server.
    When Frida receive the message `rundata` it will send back the collected data.

## Detecting ClassLoader

The first goal was to detect and retreive dex files that could be loaded at runtime with a set of class that inherit from `java.lang.ClassLoader`.

### ClassLoader from file

The simplest ClassLoader are `DexClassLoader` and `PathClassLoader`. They loaded new classes from a file on the filesystem.
The goal is to retreive the content of such files.


An example java code with such ClassLoader could look like this:
```java
String full_path = getApplicationContext().getFilesDir()+"/"+file_name;
DexClassLoader dexClassLoader = new DexClassLoader(full_path, null, null, getClass().getClassLoader());
Class<?> clz = dexClassLoader.loadClass("exampleClass");
Constructor<?> c = clz.getConstructor();
Object classInstance = c.newInstance();
Method method = clz.getMethod("exampleMethod");
method.invoke(classInstance);
```

Here, the file located at `full_path` is loaded as a dex file with the DexClassLoader. And is then used to call the `exampleClass.exampleMethod()` method.

The detect dynamic loading and retreive the loaded dex we need to hook the `DexClassLoader` constructor. This is done in `overrideClassLoaderInit()`.

```javascript
const argsList = [...];
const classLoader = Java.use('dalvik.system.DexClassLoader');
const init = classLoader.$init.overload(...argsList);
init.implementation = hook(init);
```

The above code does exactly that. It override a constructor of `DexClassLoader`, with the return value of `hook(init)`.
The following is an example of `hook` method. It uses some helper method to send the file content to the frida client controlled via python.

```javascript
function fileClassLoaderHook(init_method: Java.Method<{}>) {
  return function(this: any, ...args: any[]) {
    let dexPath = args[0];
    let filename = dexPath.split('/').slice(-1)[0] + '-' + sha256_fromFilePath(dexPath);
    send({ id: "dex", filename: filename }, getJSBufferFromJavaBuffer(getJavaBufferFromPath(dexPath)))
    return init_method.call(this, ...args);
  }
}
```

### ClassLoader from Java buffer

Another type of ClassLoader is the InMemoryBuffer, which takes as input a `ByteBuffer`.

The issue here is the traduction between a Java buffer and a JS buffer.
Because the given argument is a Java native buffer whereas the `send` method from frida takes a Javascript array/buffer.

With that in mind, the following Java code can be hooked with the same code as above but using a different hook function:
```java
ByteBuffer buffer = ByteBuffer.wrap(buffer_sliced);
InMemoryDexClassLoader inMemoryDexClassLoader = new InMemoryDexClassLoader(buffer, getClass().getClassLoader());
Class<?> clz = inMemoryDexClassLoader.loadClass("exampleClass");
```

The `memoryClassLoaderHookSetup()` is used to give the correct hook depending of the prototype of the constructor.


## Hooking dynamically loaded method

- hooks.config


## Some issue we encountered

### Android API level

