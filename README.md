# Dexcaliburn

![dexcaliburn](assets/imgs/dexcaliburn.jpg)

## A tool to extract dynamically loaded bytecode

### Installation & Build

Install frida :
 + Locally : https://frida.re/docs/installation/
 + On your Android device : https://frida.re/docs/android/

Then, install the following python requirements :

```bash
pip install androguard frida-tools pysmali
```

Build the Frida script:

```bash
cd src/frida-scripts
npm install
```

After modifying the `index.ts` file, you need to run `npm run build`.

### Run

First, run the server on the app you want with the following command :

```bash
python src/server.py com.example.app
```

With the server running, use the app to trigger the dynamic bytecode loader.

Once you are done, you can find bytecode files in `dex-files` and exceptions triggered by reflexive calls in `logs`.

### Bytecode analysis

To know where the dynamically loaded methods were invoked, you can launch the following script :

```bash
python src/analyze_dex.py [dex file]
```

