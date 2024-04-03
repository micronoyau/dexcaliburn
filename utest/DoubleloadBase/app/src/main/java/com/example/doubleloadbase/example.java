package com.example.doubleloadbase;

import android.content.Context;
import android.os.StrictMode;

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

import dalvik.system.DexClassLoader;

public class example {
    Context context;
    public example(Context context){
        this.context = context;
    }
    public String load(String arg, int arg2, Context applicationContext) {
        System.out.println(arg);
        System.out.println(arg2);
        System.out.println(applicationContext);
        System.out.println("0");
        String file_url = "https://github.com/micronoyau/dexcaliburn/raw/master/utest/loaded-classes/badclass.dex";
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
        try {
            System.out.println("1");
            URL url = new URL(file_url);
            String file_name = "doubleFile";
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();

            // Check for HTTP response code 200
            if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                InputStream input = connection.getInputStream();
                FileOutputStream output = context.openFileOutput(file_name, Context.MODE_PRIVATE);

                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = input.read(buffer)) != -1) {
                    output.write(buffer, 0, bytesRead);
                }
                output.close();
                input.close();
                connection.disconnect();
                File File = new File(context.getFilesDir() + "/" + file_name);
                DexClassLoader dexClassLoader = new DexClassLoader(context.getFilesDir() + "/" + file_name, null, null, getClass().getClassLoader());

                //Field f = ClassLoader.class.getDeclaredField("classes");
                //f.setAccessible(true);
                //System.out.println(f.get(inMemoryDexClassLoader));
                System.out.println("2");
                Class<?> clz = dexClassLoader.loadClass("s5.a");
                System.out.println("3");
                Constructor<?> c = clz.getConstructor();
                System.out.println("4");
                Object ex = c.newInstance();
                System.out.println("5");
                Method m = clz.getMethod("a");
                System.out.println("6");
                String showntext = (String) m.invoke(ex);

                File.delete();
                return showntext;
            }
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        }
        return "";
    }

    public String getOuterValue(String arg){
        outerClass outerclass = new outerClass(arg);
        System.out.println(this.context.getClassLoader());
        System.out.println(outerclass.getClass().getClassLoader());
        return outerclass.value();
    }
}
