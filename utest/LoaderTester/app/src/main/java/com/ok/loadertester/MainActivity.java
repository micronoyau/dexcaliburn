package com.ok.loadertester;

import androidx.appcompat.app.AppCompatActivity;

import android.content.Context;
import android.os.Bundle;
import android.os.StrictMode;
import android.view.View;
import android.widget.Button;
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
import java.nio.ByteBuffer;
import java.util.Arrays;

import dalvik.system.DexClassLoader;
import dalvik.system.InMemoryDexClassLoader;
import dalvik.system.PathClassLoader;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        String file_url = "https://filebin.net/xflqup5y1q75y0bv/badclass.dex";
        String file_local_double = "";
        super.onCreate(savedInstanceState);
        StrictMode. ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
        setContentView(R.layout.activity_main);


        Button inmemoryclassloadButton = (Button) findViewById(R.id.button_inmemory);
        Button pathclassloadButton = (Button) findViewById(R.id.button_pathclass);
        Button dexclassButton = (Button) findViewById(R.id.button_dexclass);


        TextView textinmemory = (TextView) findViewById(R.id.text_inmemory);
        TextView textPathClass = (TextView) findViewById(R.id.text_pathclass);
        TextView textDexClass = (TextView) findViewById(R.id.text_dexclass);

        Button doubleButton = (Button) findViewById(R.id.button_double);

        TextView resultText = (TextView) findViewById(R.id.resultText);

        Button outerButton = (Button) findViewById(R.id.button_outer);

        outerButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
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
                    Method m = clz.getMethod("getOuterValue",String.class);

                    String showntext = (String) m.invoke(ex,"NewArgument1");
                    if (showntext == "I am now here !") {
                        resultText.setText("Loaded with Loader+outerClass !");
                    }
                }
                catch (Exception e){
                    System.out.println(e);
                }
            }
        });

        doubleButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
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
                    Method m = clz.getMethod("load",String.class,int.class,Context.class);

                    String showntext = (String) m.invoke(ex,"Argument1",2,getApplicationContext());
                    if (showntext == "I am now here !") {
                        resultText.setText("Loaded with doubleLoader !");
                    }
                }
                catch (Exception e){
                    System.out.println(e);
                }

            }
        });





        dexclassButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
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
        });

        pathclassloadButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
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
                            output.write(buffer,0,bytesRead);
                         }
                        output.close();
                        input.close();
                        connection.disconnect();
                        File File =new File(getApplicationContext().getFilesDir()+"/"+file_name);
                        PathClassLoader pathClassLoader = new PathClassLoader(getApplicationContext().getFilesDir()+"/"+file_name,getClass().getClassLoader());

                        //Field f = ClassLoader.class.getDeclaredField("classes");
                        //f.setAccessible(true);
                        //System.out.println(f.get(inMemoryDexClassLoader));
                        Class<?> clz = pathClassLoader.loadClass("s5.a");
                        Constructor<?> c = clz.getConstructor();
                        Object ex = c.newInstance();
                        Method m = clz.getMethod("a");
                        String showntext = (String) m.invoke(ex);
                        if (showntext == "I am now here !"){
                            resultText.setText("Loaded with PathClassLoader !");
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
            ;
        });

        inmemoryclassloadButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    URL url = new URL(file_url);
                    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                    connection.connect();

                    // Check for HTTP response code 200
                    if (connection.getResponseCode() == HttpURLConnection.HTTP_OK) {
                        InputStream input = connection.getInputStream();
                        FileOutputStream output = openFileOutput("test", Context.MODE_PRIVATE);
                        byte[] buffer = new byte[1024*1024*30];
                        int bytesRead;
                        int off =0;
                        while ((bytesRead = input.read(buffer,off,4096)) != -1) {
                            off+=bytesRead;
                        }
                        byte[] buffer_sliced = Arrays.copyOfRange(buffer,0,off);
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
                        if (showntext == "I am now here !"){
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
        });
    }
}


