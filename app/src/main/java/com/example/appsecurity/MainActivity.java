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
import com.chrisney.enigma.EnigmaUtils;

public class MainActivity extends AppCompatActivity {
    ListView listView;
    TextView textView;
    String[] listItem;

    public static String MAIN_KEY=EnigmaUtils.enigmatization(new byte[]{-124, -55, 82, 108, 48, 14, -67, -3, -91, -45, -75, -71, 50, 39, -10, -72, -104, 69, -32, -70, -1, -99, 105, 50, 62, -22, -44, 1, 56, -8, 103, -48});
    public static String STR=EnigmaUtils.enigmatization(new byte[]{66, -113, 121, -82, -91, 15, 94, 57, -54, -69, 20, -1, 29, -23, 42, 20});

    public static final String ABRXLXCQMN = "pWYOOr9m$jN*5jA";
    MCrypt mcrypt = new MCrypt();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            String testing_base64ToString=new String(Base64.decode(EnigmaUtils.enigmatization(new byte[]{-75, 18, -63, -75, 66, -18, 52, -94, 6, -63, 9, 60, 15, 93, 90, 119, 21, -128, 57, -88, 88, 48, -61, -114, 96, 36, 105, -20, -122, -1, -13, -53}), Base64.DEFAULT), EnigmaUtils.enigmatization(new byte[]{-29, 112, 61, -116, 81, 81, 127, 35, 54, 75, -72, 29, -68, -34, -113, -125}));
            Log.i(EnigmaUtils.enigmatization(new byte[]{38, 46, 15, -33, -72, 7, 76, -87, -36, -12, -4, 14, -72, 72, -124, -26, 7, -5, 47, -61, -79, 72, -5, -68, -62, -111, -20, -41, 7, -4, 118, 19}),testing_base64ToString);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        Log.i(EnigmaUtils.enigmatization(new byte[]{-99, -102, -87, -120, 21, -9, 38, -49, 65, 37, -31, 30, 117, -92, -83, 50}),MAIN_KEY);
        Log.i(EnigmaUtils.enigmatization(new byte[]{18, -68, -28, -92, 97, -18, 32, -125, 50, -85, 38, 78, 96, -42, 10, -68}),STR);
        String encrypted_data = null;
        String decrypted;

        try {
            //encrypted_data= MCrypt.bytesToHex( mcrypt.encrypt("hello am working"));
            AesCipher encrypted = AesCipher.encrypt(EnigmaUtils.enigmatization(new byte[]{-76, 88, 84, -14, 110, 20, -65, -46, -6, 43, 3, -23, 112, 8, 7, 33, 23, -40, -69, 48, -4, 38, -38, -118, -27, 24, 108, -67, -9, -122, 40, -114}),EnigmaUtils.enigmatization(new byte[]{101, 8, 93, 70, -91, 56, 35, 89, -8, -84, 59, -49, -94, 114, -22, 17}));
            encrypted_data= encrypted.getData();
        } catch (Exception e) {
            e.printStackTrace();
        }

       // TestAES.printpass();

        try {
             //decrypted = new String( mcrypt.decrypt( encrypted_data ) );
            AesCipher aesdecr = AesCipher.decrypt(EnigmaUtils.enigmatization(new byte[]{-76, 88, 84, -14, 110, 20, -65, -46, -6, 43, 3, -23, 112, 8, 7, 33, 23, -40, -69, 48, -4, 38, -38, -118, -27, 24, 108, -67, -9, -122, 40, -114}), encrypted_data);
            decrypted = aesdecr.getData();


            Log.i(EnigmaUtils.enigmatization(new byte[]{96, 36, 106, 75, -62, -17, 79, -82, -120, 103, -37, -76, -78, 1, -125, 8}),EnigmaUtils.enigmatization(new byte[]{-37, -90, 95, -66, -35, 76, 80, -5, -127, 6, 53, -39, -60, 54, 41, 41})+encrypted_data);
           Log.i(EnigmaUtils.enigmatization(new byte[]{-3, 119, 38, 56, -117, 119, 46, 53, 103, 89, -64, -36, -33, 111, 102, -86, -116, -98, 55, -24, 125, 57, 30, -39, 117, 79, -94, -68, -6, 59, -27, 23}),EnigmaUtils.enigmatization(new byte[]{-37, -90, 95, -66, -35, 76, 80, -5, -127, 6, 53, -39, -60, 54, 41, 41})+decrypted);

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
        if (ABRXLXCQMN.isEmpty()) ABRXLXCQMN.getClass().toString();
    }
}
