import { writeFileSync } from "./frida-fs.js";
import { LOG_LEVEL } from "./index.js";

export function log(message: string): void {
    if(LOG_LEVEL>0) {
        console.log(message);
    }
}

export function log2(message: string): void {
    if(LOG_LEVEL>1) {
        console.log(message);
    }
}

export function debounce(func: any, timeout = 300){
  let timer: ReturnType<typeof setTimeout>;
  return function (this: any, ...args: any[]) {
    clearTimeout(timer);
    timer = setTimeout(() => { func.apply(this, args); }, timeout);
  };
}

export function readFile(input_file: string, bsize=4096) {
    // from dexcalibur
    var fin = Java.use("java.io.FileInputStream").$new(input_file);
    // var content : Array<any> = [];
    var content : Array<any> = [];
    var b=null;
    var jsBuffer = new Uint8Array(bsize);
    var buffer = Java.array('byte', Array.from(jsBuffer));
    do{
        b=fin.read(buffer);
        if(b != -1) {
            // TODO : change read file method
            for (var i=0; i<b; i++) {
                content.push(buffer[i]);
            }
        }
    } while(b != -1);
    return content;
}
