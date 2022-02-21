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

public class MCrypt {

    static char[] HEX_CHARS = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

    private String iv = "fedcba9876543210";//Dummy iv (CHANGE IT!)
    private IvParameterSpec ivspec;
    private SecretKeySpec keyspec;
    private Cipher cipher;

    private String SecretKey = "25c6c7ff35b9979b151f2136cd13b0ff";//Dummy secretKey (CHANGE IT!)

    public MCrypt()
    {

        try {
        keyspec = new SecretKeySpec(SecretKey.getBytes("UTF-8"), "AES");

            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
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
        if(text == null || text.length() == 0)
            throw new Exception("Empty string");

        byte[] encrypted = null;

        try {
            cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);

            encrypted = cipher.doFinal(padString(text).getBytes());
        } catch (Exception e)
        {
            throw new Exception("[encrypt] " + e.getMessage());
        }

        return encrypted;
    }

    public byte[] decrypt(String code) throws Exception
    {
        if(code == null || code.length() == 0)
            throw new Exception("Empty string");

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
            throw new Exception("[decrypt] " + e.getMessage());
        }
        return decrypted;
    }


    private static byte[] getBytes(String str) throws UnsupportedEncodingException {
        return str.getBytes("UTF-8");
    }

    public static String encrypt2(@NotNull String input, @NotNull String key) throws UnsupportedEncodingException {
        byte[] bytes = Base64.encode(getBytes(input),Base64.DEFAULT);
        if (bytes.length < 17) {
            return null;
        }

        byte[] ivBytes = Arrays.copyOfRange(bytes, 0, 16);
        byte[] contentBytes = Arrays.copyOfRange(bytes, 16, bytes.length);


        try {
            Cipher ciper = Cipher.getInstance("AES/CBC/PKCS5Padding");

            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
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
            Cipher ciper = Cipher.getInstance("AES/CBC/PKCS5Padding");

            SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
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
