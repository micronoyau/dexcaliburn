# Dexcaliburn

![dexcaliburn](assets/imgs/dexcaliburn.jpg)

## A tool to extract dynamically loaded bytecode

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

First, launch the server on the target app with the following command :

```bash
python src/server.py com.example.app out.json
```

You can now use the app to trigger dynamic class loading.

Once you are done, press enter to save your results. The bytecode files can be found in `dex-files` and reflexive calls are logged in the JSON file.

### Bytecode analysis

[TODO]

To know where the dynamically loaded methods were invoked, you can launch the following script :

```bash
python src/analyze_dex.py [dex file]
```

