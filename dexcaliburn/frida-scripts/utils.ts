import { LOG_LEVEL } from "./index.js";

export function log(message: string): void {
  if (LOG_LEVEL > 0) {
    console.log(message);
  }
}

export function log2(message: string): void {
  if (LOG_LEVEL > 1) {
    console.log(message);
  }
}

export function debounce(func: any, timeout = 300) {
  let timer: ReturnType<typeof setTimeout>;
  return function(this: any, ...args: any[]) {
    clearTimeout(timer);
    timer = setTimeout(() => { func.apply(this, args); }, timeout);
  };
}

export function makeid(length: number) {
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

function toHexString(byteArray: any[]) {
  return Array.from(byteArray, function(byte) {
    return ('0' + (byte & 0xFF).toString(16)).slice(-2);
  }).join('')
}

export function getJSBufferFromJavaBuffer(buffer: any): any[] {
  // https://github.com/frida/frida/issues/1281
  const jsonString = Java.use('org.json.JSONArray').$new(buffer).toString();
  return JSON.parse(jsonString);
}

export function getJavaBufferFromPath(pathString: string): any {
  const path = Java.use('java.nio.file.Paths').get(pathString, []);
  return Java.use('java.nio.file.Files').readAllBytes(path);
}

export function sha256_fromJavaBuffer(buffer: any) {
  const md = Java.use('java.security.MessageDigest').getInstance('SHA-256');
  md.update(buffer);
  if (buffer.rewind) {
    buffer.rewind();
  }
  return toHexString(md.digest());
}

export function sha256_fromFilePath(pathString: string) {
  return sha256_fromJavaBuffer(getJavaBufferFromPath(pathString));
}
