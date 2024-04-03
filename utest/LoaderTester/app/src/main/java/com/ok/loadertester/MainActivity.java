package com.ok.loadertester;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.os.StrictMode;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.Spinner;
import android.widget.TextView;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.ByteBuffer;
import java.util.Arrays;

import dalvik.system.BaseDexClassLoader;
import dalvik.system.DelegateLastClassLoader;
import dalvik.system.DexClassLoader;
import dalvik.system.InMemoryDexClassLoader;
import dalvik.system.PathClassLoader;

public class MainActivity extends AppCompatActivity {
    String file_url = "https://github.com/micronoyau/dexcaliburn/raw/master/utest/loaded-classes/badclass.dex";
    TextView resultText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
        setContentView(R.layout.activity_main);



        TextView resultText = (TextView) findViewById(R.id.resultText);
        this.resultText = resultText;

        Spinner spinner = (Spinner) findViewById(R.id.method_spinner);
        String[] items = new String[]{"baseDexClassLoader","dexClassLoader", "pathClassLoader", "inMemoryClassLoader","delegateLastClassLoader","urlClassLoader", "pathClassLoader + outerClass", "dexClassLoader in PathClassLoader"};
        ArrayAdapter<CharSequence> adapter = new ArrayAdapter<>(this, androidx.appcompat.R.layout.support_simple_spinner_dropdown_item, items);
        spinner.setAdapter(adapter);

        Button testButton = (Button) findViewById(R.id.test_button);

        testButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                switch (items[spinner.getSelectedItemPosition()]) {
                    case "dexClassLoader":
                        test_dexClassLoader();
                        break;
                    case "pathClassLoader":
                        test_pathClassLoader();
                        break;
                    case "inMemoryClassLoader":
                        test_inMemoryClassLoader();
                        break;
                    case "pathClassLoader + outerClass":
                        test_pathClassAndOuterClass();
                        break;
                    case "urlClassLoader":
                        test_urlClassLoader();
                        break;
                    case "dexClassLoader in PathClassLoader":
                        test_doubleClass();
                        break;
                    case "baseDexClassLoader":
                        test_baseDexClassLoader();
                        break;
                    case "delegateLastClassLoader":
                        test_delegateLastClassLoader();
                        break;
                }

            }
        });
    }

    private void test_baseDexClassLoader(){
        try {
            URL url = new URL(file_url);
            String file_name = "dexdexFile";
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();

            // Check for HTTP response code 200
            if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                InputStream input = connection.getInputStream();
                FileOutputStream output = openFileOutput(file_name, Context.MODE_PRIVATE);

                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = input.read(buffer)) != -1) {
                    output.write(buffer,0,bytesRead);
                }
                output.close();
                input.close();
                connection.disconnect();
                File File =new File(getApplicationContext().getFilesDir()+"/"+file_name);
                BaseDexClassLoader baseDexClassLoader = new BaseDexClassLoader(getApplicationContext().getFilesDir()+"/"+file_name,null,null,getClass().getClassLoader());

                //Field f = ClassLoader.class.getDeclaredField("classes");
                //f.setAccessible(true);
                //System.out.println(f.get(inMemoryDexClassLoader));
                Class<?> clz = baseDexClassLoader.loadClass("s5.a");
                Constructor<?> c = clz.getConstructor();
                Object ex = c.newInstance();
                Method m = clz.getMethod("a");
                String showntext = (String) m.invoke(ex);
                if (showntext == "I am now here !"){
                    resultText.setText("Loaded with baseDexClassLoader !");
                }
                File.delete();
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
    }
    private void test_dexClassLoader() {
        try {
            URL url = new URL(file_url);
            String file_name = "dexdexFile";
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();

            // Check for HTTP response code 200
            if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                InputStream input = connection.getInputStream();
                FileOutputStream output = openFileOutput(file_name, Context.MODE_PRIVATE);

                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = input.read(buffer)) != -1) {
                    output.write(buffer,0,bytesRead);
                }
                output.close();
                input.close();
                connection.disconnect();
                File File =new File(getApplicationContext().getFilesDir()+"/"+file_name);
                DexClassLoader dexClassLoader = new DexClassLoader(getApplicationContext().getFilesDir()+"/"+file_name,null,null,getClass().getClassLoader());

                //Field f = ClassLoader.class.getDeclaredField("classes");
                //f.setAccessible(true);
                //System.out.println(f.get(inMemoryDexClassLoader));
                Class<?> clz = dexClassLoader.loadClass("s5.a");
                Constructor<?> c = clz.getConstructor();
                Object ex = c.newInstance();
                Method m = clz.getMethod("a");
                String showntext = (String) m.invoke(ex);
                if (showntext == "I am now here !"){
                    resultText.setText("Loaded with dexClassLoader !");
                }
                File.delete();
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
    }
    private void test_pathClassLoader() {
        try {
            URL url = new URL(file_url);

            String file_name = "pathdexFile";
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            connection.connect();

            // Check for HTTP response code 200
            if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                InputStream input = connection.getInputStream();
                FileOutputStream output = openFileOutput(file_name, Context.MODE_PRIVATE);

                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = input.read(buffer)) != -1) {
                    output.write(buffer, 0, bytesRead);
                }
                output.close();
                input.close();
                connection.disconnect();
                File File = new File(getApplicationContext().getFilesDir() + "/" + file_name);
                PathClassLoader pathClassLoader = new PathClassLoader(getApplicationContext().getFilesDir() + "/" + file_name, getClass().getClassLoader());
                System.out.println("2");

                //Field f = ClassLoader.class.getDeclaredField("classes");
                //f.setAccessible(true);
                //System.out.println(f.get(inMemoryDexClassLoader));
                Class<?> clz = pathClassLoader.loadClass("s5.a");
                Constructor<?> c = clz.getConstructor();
                Object ex = c.newInstance();
                Method m = clz.getMethod("a");
                String showntext = (String) m.invoke(ex);
                if (showntext == "I am now here !") {
                    resultText.setText("Loaded with PathClassLoader !");
                }
                File.delete();
            }
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            System.out.println(e);
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
    }
    private void test_inMemoryClassLoader() {
        try {
            URL url = new URL(file_url);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();

            // Check for HTTP response code 200
            if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                InputStream input = connection.getInputStream();
                FileOutputStream output = openFileOutput("test", Context.MODE_PRIVATE);
                byte[] buffer = new byte[1024 * 1024 * 30];
                int bytesRead;
                int off = 0;
                while ((bytesRead = input.read(buffer, off, 4096)) != -1) {
                    off += bytesRead;
                }
                byte[] buffer_sliced = Arrays.copyOfRange(buffer, 0, off);
                output.write(buffer_sliced);

                input.close();

                connection.disconnect();
                InMemoryDexClassLoader inMemoryDexClassLoader = new InMemoryDexClassLoader(ByteBuffer.wrap(buffer_sliced), getClass().getClassLoader());

                //Field f = ClassLoader.class.getDeclaredField("classes");
                //f.setAccessible(true);

                //System.out.println(f.get(inMemoryDexClassLoader));
                Class<?> clz = inMemoryDexClassLoader.loadClass("s5.a");
                Constructor<?> c = clz.getConstructor();
                Object ex = c.newInstance();
                Method m = clz.getMethod("a");
                String showntext = (String) m.invoke(ex);
                if (showntext == "I am now here !") {
                    resultText.setText("Loaded with inMemoryLoader !");
                }

            }
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        } catch (InvocationTargetException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        }
    }
    private void test_delegateLastClassLoader(){
        try {
            URL url = new URL(file_url);

            String file_name = "pathdexFile";
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();

            connection.connect();

            // Check for HTTP response code 200
            if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                InputStream input = connection.getInputStream();
                FileOutputStream output = openFileOutput(file_name, Context.MODE_PRIVATE);

                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = input.read(buffer)) != -1) {
                    output.write(buffer, 0, bytesRead);
                }
                output.close();
                input.close();
                connection.disconnect();
                File File = new File(getApplicationContext().getFilesDir() + "/" + file_name);
                DelegateLastClassLoader delegateLastClassLoader = new DelegateLastClassLoader(getApplicationContext().getFilesDir() + "/" + file_name, getClass().getClassLoader());
                System.out.println("2");

                //Field f = ClassLoader.class.getDeclaredField("classes");
                //f.setAccessible(true);
                //System.out.println(f.get(inMemoryDexClassLoader));
                Class<?> clz = delegateLastClassLoader.loadClass("s5.a");
                Constructor<?> c = clz.getConstructor();
                Object ex = c.newInstance();
                Method m = clz.getMethod("a");
                String showntext = (String) m.invoke(ex);
                if (showntext == "I am now here !") {
                    resultText.setText("Loaded with delegateLastClassLoader !");
                }
                File.delete();
            }
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            System.out.println(e);
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
    }
    private void test_urlClassLoader(){
        resultText.setText("NOT SUPPORTED YET !");
    }
    private void test_pathClassAndOuterClass(){
        try {
            File file = new File(getApplicationContext().getDir("double", 0), "double" + ".dex");

            InputStream open = getApplicationContext().getAssets().open("double");
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            byte[] bArr = new byte[64];
            while (true) {
                int read = open.read(bArr);
                if (read == -1)
                    break;
                fileOutputStream.write(bArr, 0, read);
            }

            fileOutputStream.flush();
            fileOutputStream.close();
            open.close();
            PathClassLoader classLoader = new PathClassLoader(file.getAbsolutePath(), getClass().getClassLoader());
            //Class<?> clz = classLoader.loadClass("q3.a");
            Class<?> clz = classLoader.loadClass("com.example.doubleloadbase.example");
            Constructor<?>[] ci = clz.getConstructors();
            Constructor<?> c = clz.getConstructor(Context.class);

            Object ex = c.newInstance(getApplicationContext());
            Method m = clz.getMethod("getOuterValue", String.class);

            String showntext = (String) m.invoke(ex, "NewArgument1");
            if (showntext == "I am now here !") {
                resultText.setText("Loaded with Loader+outerClass !");
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }
    private void test_doubleClass(){
        try {
            File file = new File(getApplicationContext().getDir("double", 0), "double" + ".dex");

            InputStream open = getApplicationContext().getAssets().open("double");
            FileOutputStream fileOutputStream = new FileOutputStream(file);
            byte[] bArr = new byte[64];
            while (true) {
                int read = open.read(bArr);
                if (read == -1)
                    break;
                fileOutputStream.write(bArr, 0, read);
            }

            fileOutputStream.flush();
            fileOutputStream.close();
            open.close();
            PathClassLoader classLoader = new PathClassLoader(file.getAbsolutePath(), getClass().getClassLoader());
            //Class<?> clz = classLoader.loadClass("q3.a");
            Class<?> clz = classLoader.loadClass("com.example.doubleloadbase.example");
            Constructor<?>[] ci = clz.getConstructors();
            Constructor<?> c = clz.getConstructor(Context.class);

            Object ex = c.newInstance(getApplicationContext());
            Method m = clz.getMethod("load", String.class, int.class, Context.class);

            String showntext = (String) m.invoke(ex, "Argument1", 2, getApplicationContext());
            if (showntext == "I am now here !") {
                resultText.setText("Loaded with doubleLoader !");
            }
        } catch (Exception e) {
            System.out.println(e);
        }
    }



}


