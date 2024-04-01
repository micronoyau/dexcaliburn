# Dexcaliburn

![dexcaliburn](assets/imgs/dexcaliburn.jpg)

## A tool to extract dynamically loaded bytecode

### Supported features

| Feature | Support |
|---------|---------|
| DexClassLoader hook | Full :white_check_mark: |
| PathClassLoader hook | Full :white_check_mark: |
| InMemoryClassLoader hook | Full :white_check_mark: |
| URLClassLoader hook | No :no_entry_sign: |
| DelegateLastClassLoader hook | Full :white_check_mark: |
| SecureClassLoader hook | No :no_entry_sign: |
| Reflexive call xrefs | Full :white_check_mark: |
| Double load | Full :white_check_mark: |
| Custom ClassLoader | Partial :large_orange_diamond: |


### Installation & Build

First, install Frida :
 + Locally : https://frida.re/docs/installation/ (`pip install frida-tools`)
 + On your Android device : https://frida.re/docs/android/

Then, install the following python requirements :

```bash
pip install androguard pysmali
```

Build the Frida script:

```bash
cd src/frida-scripts
npm install
npm run build
```

Every time `index.ts` is modified, you need to run `npm run build`.

### Usage

`dexcaliburn` provides the following command-line options :
```bash
$ python src/dexcaliburn.py -h
usage: Dexcaliburn [-h] [-o OUTPUT] [-i INPUT] [-a APP] {run,filter}

Dexcaliburn : a tool to extract and analyze dynamically loaded android bytecode.
Features :
    + initiates a connection with Frida
    + fetches loaded DEX files
    + outputs a JSON file with reflexive calls xrefs for further analysis

positional arguments:
  {run,filter}          Action to perform

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output JSON file
  -i INPUT, --input INPUT
                        Input JSON file
  -a APP, --app APP     Target application
```

Once you are done, press enter to save your results. The bytecode files can be found in `dex-files` and reflexive calls are logged in the JSON file.

### Test App

A test app `LoaderTester` is available and ready to use in order to check how the tool handles edge cases.

The source code is in `utest/LoaderTester` and the builded apk is located at `utest/apk/loader-tester.apk`.

The app allows to test multiple kind of dynamic loading by clicking on buttons. If successful, a text is shown at the bottom of the screen.  

| Test | Description |
|---------|---------|
| dexClassLoader | Downloads a dex-file from an online filebin and loads a class through dexClassLoader  |
| PathClassLoader | Downloads a dex-file from an online filebin and loads a class through pathClassLoader |
| PathClassLoader + outerClass | Loads a class from a local dex-file through pathClassLoader. The loaded class instantiates another class through the "new" keyword |
| inMemoryClassLoader | Stores a dex-file fetched from an online filebin in a buffer and loads a class through inMemoryClassLoader |
| DexClass inside PathClass | Loads a class from a local dex-file through pathClassLoader. The loaded class downloads a dex-file from an online filebin and loads itself another class through dexClassLoader |

### Example

In the following example, the test app is analyzed using `dexcaliburn` :

```bash
$ python src/dexcaliburn.py -a com.ok.loadertester -o loadertester.json run
Welcome to dexcaliburn ! To exit, press [enter]
Got message of type: setup
```

The DexClass inside PathClass option is selected, which triggers dynamic loading :

```bash
Loading new dex from file: /data/user/0/com.ok.loadertester/app_double/double.dex
Sending dex as 'double.dex-78734283222b7bb21a2ac5f7dec364bd6fbb16d17053a5a3494abe2e57dc0943'
Got message of type: dex
```

Once the analysis is over, press `[enter]` :

```
Got message of type: rundata

===== Unfiltered output (saved in loadertester.json) =====
{
  "dexFiles": [
    "double.dex-78734283222b7bb21a2ac5f7dec364bd6fbb16d17053a5a3494abe2e57dc0943"
  ],
  "xrefs": [
    {
      "method": {
        "className": "android.view.ViewGroup",
        "methodName": "makeOptionalFitsSystemWindows",
        "prototype": "public void()"
      },
      "location": {
        "callingMethod": "d.b0.w",
        "position": 299,
        "source": "debug"
      },
      "count": 1
    },
    {
      "method": {
        "className": "android.view.View",
        "methodName": "getElevation",
        "prototype": "public float()"
      },
      "location": {
        "callingMethod": "android.animation.PropertyValuesHolder.setupSetterAndGetter",
        "position": 852,
        "source": "debug"
      },
      "count": 1
    },
    {
      "method": {
        "className": "android.view.View",
        "methodName": "getTranslationZ",
        "prototype": "public float()"
      },
      "location": {
        "callingMethod": "android.animation.PropertyValuesHolder.setupSetterAndGetter",
        "position": 852,
        "source": "debug"
      },
      "count": 1
    },
    {
      "method": {
        "className": "android.view.View",
        "methodName": "getTransitionAlpha",
        "prototype": "public float()"
      },
      "location": {
        "callingMethod": "android.animation.PropertyValuesHolder.setupSetterAndGetter",
        "position": 852,
        "source": "debug"
      },
      "count": 2
    },
    {
      "method": {
        "className": "com.example.doubleloadbase.example",
        "methodName": "getOuterValue",
        "prototype": "public java.lang.String(java.lang.String)"
      },
      "location": {
        "callingMethod": "com.ok.loadertester.MainActivity.p",
        "position": 126,
        "source": "debug"
      },
      "count": 1
    }
  ]
}
Press 'f' to filter output
```

To remove all unrelevant cross-references found by Frida, either press `f` or use the `filter` command-line action :

```bash
f
Filtering xrefs ...
Filtered output (saved to loadertester-filtered.json):
{
  "dexFiles": [
    "double.dex-78734283222b7bb21a2ac5f7dec364bd6fbb16d17053a5a3494abe2e57dc0943"
  ],
  "xrefs": [
    {
      "method": {
        "className": "com.example.doubleloadbase.example",
        "methodName": "getOuterValue",
        "prototype": "public java.lang.String(java.lang.String)"
      },
      "location": {
        "callingMethod": "com.ok.loadertester.MainActivity.p",
        "position": 126,
        "source": "debug"
      },
      "count": 1,
      "dexFile": "double.dex-78734283222b7bb21a2ac5f7dec364bd6fbb16d17053a5a3494abe2e57dc0943"
    }
  ]
}
```
