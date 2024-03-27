package com.example.doubleloadbase;

import android.os.Bundle;
import android.os.StrictMode;
import androidx.appcompat.app.AppCompatActivity;

/* loaded from: /home/devilsharu/AndroidStudioProjects/LoaderTester/app/src/main/assets/double */
public class MainActivity extends AppCompatActivity {
    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        StrictMode.setThreadPolicy(new StrictMode.ThreadPolicy.Builder().permitAll().build());
        try {
            System.out.println(new example(getApplicationContext()).load("aa", 3, getApplicationContext()));
        } catch (Exception e) {
            System.out.println(e);
        }
    }
}