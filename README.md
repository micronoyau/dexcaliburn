# Dexcaliburn

![dexcaliburn](assets/imgs/dexcaliburn.jpg)

## A tool to extract dynamically loaded bytecode

### Installation & Build

Install frida locally and on the emulator

Install python requierments (frida & androguard):

```
pip install androguard frida-tools
```

Build the Frida script:

```bash
cd src/frida-scripts
npm install
```

After modifying the `index.ts` file, you need to run `npm run build`.

### Run

First, run the server on the app you want with the following command :

```
python src/server.py com.example.app
```

With the server running, use the app to trigger the dynamic bytecode loader.

Once you are done, you can find bytecode files in `dex-files` and exceptions triggered by reflexive calls in `logs`.

### Bytecode analysis

To know where the dynamically loaded methods are invoked, you can launch the following script :

```
python src/analyze_dex.py [dex file]
```

