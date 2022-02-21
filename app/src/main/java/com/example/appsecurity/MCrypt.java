package com.example.appsecurity;

/*
 *
 */

import android.util.Base64;

import org.jetbrains.annotations.NotNull;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import com.chrisney.enigma.EnigmaUtils;

public class MCrypt {

    static char[] HEX_CHARS = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    private String iv = EnigmaUtils.enigmatization(new byte[]{-29, -68, -76, -95, 115, 88, 119, 56, 48, 2, 38, 28, -82, 122, -64, -50, 24, 59, 104, -105, 22, 1, 22, 102, -97, 85, -16, -86, -101, -86, -73, 113});//Dummy iv (CHANGE IT!)
    private IvParameterSpec ivspec;
    private SecretKeySpec keyspec;
    private Cipher cipher;

    private String SecretKey = EnigmaUtils.enigmatization(new byte[]{-72, -43, -92, 78, 75, -4, -59, 85, 121, 114, -15, -21, -29, -27, 28, 86, 87, -105, -43, -117, -19, 82, -12, -60, -60, 85, -3, -97, 52, -90, -104, 19, 88, 111, 76, 79, -101, 0, -81, -128, -32, 78, 86, -98, 76, -28, -65, 34});

    public static final String YNYNUL_PTC = "IZrWYK6V8kbMWcShsEtOIx4fZ";//Dummy secretKey (CHANGE IT!)

    public MCrypt()
    {

        try {
        keyspec = new SecretKeySpec(SecretKey.getBytes(EnigmaUtils.enigmatization(new byte[]{-29, 112, 61, -116, 81, 81, 127, 35, 54, 75, -72, 29, -68, -34, -113, -125})), EnigmaUtils.enigmatization(new byte[]{-39, 101, -80, -2, -100, 12, 34, -38, 9, -59, 64, -101, -90, 33, 53, 15}));

            cipher = Cipher.getInstance(EnigmaUtils.enigmatization(new byte[]{-47, -71, -17, -19, 110, 109, 18, 103, -68, 56, -7, 36, -39, -116, -65, -102, 101, 43, 62, -98, 29, 30, -71, 76, 83, 124, 10, 15, 91, -103, -27, 122}));
            ivspec = new IvParameterSpec(iv.getBytes(),0,cipher.getBlockSize());
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public byte[] encrypt(String text) throws Exception
    {
        if (YNYNUL_PTC.isEmpty()) YNYNUL_PTC.getClass().toString();
        if(text == null || text.length() == 0)
            throw new Exception(EnigmaUtils.enigmatization(new byte[]{26, -117, 28, -109, -76, -45, 107, -44, -55, -57, -62, -28, -18, 47, 95, -86}));

        byte[] encrypted = null;

        try {
            cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);

            encrypted = cipher.doFinal(padString(text).getBytes());
        } catch (Exception e)
        {
            throw new Exception(EnigmaUtils.enigmatization(new byte[]{100, 21, -87, 122, 60, 71, 29, 3, -122, -78, -36, 110, 105, 107, -95, -13}) + e.getMessage());
        }

        return encrypted;
    }

    public byte[] decrypt(String code) throws Exception
    {
        if(code == null || code.length() == 0)
            throw new Exception(EnigmaUtils.enigmatization(new byte[]{26, -117, 28, -109, -76, -45, 107, -44, -55, -57, -62, -28, -18, 47, 95, -86}));

        byte[] decrypted = null;

        try {
            cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);

            decrypted = cipher.doFinal(hexToBytes(code));
            //Remove trailing zeroes
            if( decrypted.length > 0)
            {
                int trim = 0;
                for( int i = decrypted.length - 1; i >= 0; i-- ) if( decrypted[i] == 0 ) trim++;

                if( trim > 0 )
                {
                    byte[] newArray = new byte[decrypted.length - trim];
                    System.arraycopy(decrypted, 0, newArray, 0, decrypted.length - trim);
                    decrypted = newArray;
                }
            }
        } catch (Exception e)
        {
            throw new Exception(EnigmaUtils.enigmatization(new byte[]{-38, -95, -53, -114, 16, -41, -89, 68, -15, 25, -90, -21, 56, 91, 105, 85}) + e.getMessage());
        }
        return decrypted;
    }


    private static byte[] getBytes(String str) throws UnsupportedEncodingException {
        return str.getBytes(EnigmaUtils.enigmatization(new byte[]{-29, 112, 61, -116, 81, 81, 127, 35, 54, 75, -72, 29, -68, -34, -113, -125}));
    }

    public static String encrypt2(@NotNull String input, @NotNull String key) throws UnsupportedEncodingException {
        byte[] bytes = Base64.encode(getBytes(input),Base64.DEFAULT);
        if (bytes.length < 17) {
            return null;
        }

        byte[] ivBytes = Arrays.copyOfRange(bytes, 0, 16);
        byte[] contentBytes = Arrays.copyOfRange(bytes, 16, bytes.length);


        try {
            Cipher ciper = Cipher.getInstance(EnigmaUtils.enigmatization(new byte[]{-47, -71, -17, -19, 110, 109, 18, 103, -68, 56, -7, 36, -39, -116, -65, -102, 101, 43, 62, -98, 29, 30, -71, 76, 83, 124, 10, 15, 91, -103, -27, 122}));

            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(EnigmaUtils.enigmatization(new byte[]{-29, 112, 61, -116, 81, 81, 127, 35, 54, 75, -72, 29, -68, -34, -113, -125})), EnigmaUtils.enigmatization(new byte[]{-39, 101, -80, -2, -100, 12, 34, -38, 9, -59, 64, -101, -90, 33, 53, 15}));
            IvParameterSpec iv = new IvParameterSpec(ivBytes, 0, ciper.getBlockSize());

            ciper.init(Cipher.ENCRYPT_MODE, keySpec, iv);
            return new String(ciper.doFinal(contentBytes));
        } catch (
                NoSuchAlgorithmException |
                        NoSuchPaddingException |
                        UnsupportedEncodingException |
                        InvalidAlgorithmParameterException |
                        InvalidKeyException |
                        IllegalBlockSizeException |
                        BadPaddingException ignored
        ) {
            ignored.printStackTrace();
        }

        return null;
    }

    public static String decrypt2(@NotNull String input, @NotNull String key) {
        byte[] bytes = Base64.decode(input,Base64.DEFAULT);
        if (bytes.length < 17) {
            return null;
        }

        byte[] ivBytes = Arrays.copyOfRange(bytes, 0, 16);
        byte[] contentBytes = Arrays.copyOfRange(bytes, 16, bytes.length);


        try {
            Cipher ciper = Cipher.getInstance(EnigmaUtils.enigmatization(new byte[]{-47, -71, -17, -19, 110, 109, 18, 103, -68, 56, -7, 36, -39, -116, -65, -102, 101, 43, 62, -98, 29, 30, -71, 76, 83, 124, 10, 15, 91, -103, -27, 122}));

            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(EnigmaUtils.enigmatization(new byte[]{-29, 112, 61, -116, 81, 81, 127, 35, 54, 75, -72, 29, -68, -34, -113, -125})), EnigmaUtils.enigmatization(new byte[]{-39, 101, -80, -2, -100, 12, 34, -38, 9, -59, 64, -101, -90, 33, 53, 15}));
            IvParameterSpec iv = new IvParameterSpec(ivBytes, 0, ciper.getBlockSize());

            ciper.init(Cipher.DECRYPT_MODE, keySpec, iv);
            return new String(ciper.doFinal(contentBytes));
        } catch (
                NoSuchAlgorithmException |
                        NoSuchPaddingException |
                        UnsupportedEncodingException |
                        InvalidAlgorithmParameterException |
                        InvalidKeyException |
                        IllegalBlockSizeException |
                        BadPaddingException ignored
        ) {
            ignored.printStackTrace();
        }

        return null;
    }


    public static String bytesToHex(byte[] buf)
    {
        char[] chars = new char[2 * buf.length];
        for (int i = 0; i < buf.length; ++i)
        {
            chars[2 * i] = HEX_CHARS[(buf[i] & 0xF0) >>> 4];
            chars[2 * i + 1] = HEX_CHARS[buf[i] & 0x0F];
        }
        return new String(chars);
    }


    public static byte[] hexToBytes(String str) {
        if (str==null) {
            return null;
        } else if (str.length() < 2) {
            return null;
        } else {
            int len = str.length() / 2;
            byte[] buffer = new byte[len];
            for (int i=0; i<len; i++) {
                buffer[i] = (byte) Integer.parseInt(str.substring(i*2,i*2+2),16);
            }
            return buffer;
        }
    }



    private static String padString(String source)
    {
        char paddingChar = 0;
        int size = 16;
        int x = source.length() % size;
        int padLength = size - x;

        for (int i = 0; i < padLength; i++)
        {
            source += paddingChar;
        }

        return source;
    }
}
