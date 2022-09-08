package com.tasks.decryption_encryption;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import android.os.Build;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class MainActivity extends AppCompatActivity {


    Button btnEncrypt;
    Button btnDecrypt;
    TextView txtShower;
    EditText et_msg;
    CryptoManager cryptoManager;

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        btnEncrypt = findViewById(R.id.mainActivity_btnEncrypt);
        btnDecrypt = findViewById(R.id.mainActivity_btnDecrypt);
        txtShower = findViewById(R.id.mainActivity_txtShower);
        et_msg = findViewById(R.id.mainActivity_decryptMSG);


        btnEncrypt.setOnClickListener((v -> {
            cryptoManager = new CryptoManager();

            String msg = et_msg.getText().toString();
            byte[] bytes = msg.getBytes();
            File file = new File(getFilesDir(), "secret.txt");
            if (!file.exists()) {
                try {
                    file.createNewFile();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            try {
                FileOutputStream fileOutputStream = new FileOutputStream(file);
                byte[] encrypt = cryptoManager.encrypt(
                        bytes, fileOutputStream
                );
                String encryptedMsg = new String(encrypt, StandardCharsets.UTF_8);
                txtShower.setText(encryptedMsg);
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }

        }));
        btnDecrypt.setOnClickListener((v -> {
            cryptoManager = new CryptoManager();

            File file = new File(getFilesDir(), "secret.txt");
            try {
                byte[] decrypt = cryptoManager.decrypt(new FileInputStream(file));
                txtShower.setText(new String(decrypt, StandardCharsets.UTF_8));

            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }));
    }
}