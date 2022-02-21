package com.example.appsecurity;

import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.UnsupportedEncodingException;

public class MainActivity extends AppCompatActivity {
    ListView listView;
    TextView textView;
    String[] listItem;

    public static String MAIN_KEY="HELLO_WORLD_123456";
    public static String STR="HELLO_123456";
    MCrypt mcrypt = new MCrypt();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            String testing_base64ToString=new String(Base64.decode("MjZrb3pRYUt3UnVOSjI0dA==", Base64.DEFAULT), "UTF-8");
            Log.i("testing_base64ToString",testing_base64ToString);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        Log.i("main_key",MAIN_KEY);
        Log.i("STR",STR);
        String encrypted_data = null;
        String decrypted;

        try {
            //encrypted_data= MCrypt.bytesToHex( mcrypt.encrypt("hello am working"));
            AesCipher encrypted = AesCipher.encrypt("26kozQaKwRuNJ24t","i am don");
            encrypted_data= encrypted.getData();
        } catch (Exception e) {
            e.printStackTrace();
        }

       // TestAES.printpass();

        try {
             //decrypted = new String( mcrypt.decrypt( encrypted_data ) );
            AesCipher aesdecr = AesCipher.decrypt("26kozQaKwRuNJ24t", encrypted_data);
            decrypted = aesdecr.getData();


            Log.i("encrypted_data",""+encrypted_data);
           Log.i("encrypted_data dec",""+decrypted);

        } catch (Exception e) {
            e.printStackTrace();
        }

        listView = (ListView) findViewById(R.id.listView);
        textView = (TextView) findViewById(R.id.textView);
        listItem = getResources().getStringArray(R.array.array_technology);
        final ArrayAdapter<String> adapter = new ArrayAdapter<String>(this,
                android.R.layout.simple_list_item_1, android.R.id.text1, listItem);
        listView.setAdapter(adapter);

        listView.setOnItemClickListener((adapterView, view, position, l) -> {
            // TODO Auto-generated method stub
            String value = adapter.getItem(position);
            Toast.makeText(getApplicationContext(), value, Toast.LENGTH_SHORT).show();

        });
    }
}