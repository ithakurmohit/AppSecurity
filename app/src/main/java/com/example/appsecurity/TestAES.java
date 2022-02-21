package com.example.appsecurity;

import android.annotation.SuppressLint;
import android.util.Base64;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class TestAES {

    private static String PASSWORD = "password";
    private static String SALT = "123456789";

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static KeyPair getKeyPair() {
        try {
            KeyPairGenerator instance = KeyPairGenerator.getInstance("RSA");
            instance.initialize(4096);
            return instance.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    private static Key generateKey() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
        return new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
                .generateSecret(new PBEKeySpec(PASSWORD.toCharArray(), getBytes(SALT), 65536, 128)).getEncoded(), "AES");
    }

    private static byte[] getBytes(String str) throws UnsupportedEncodingException {
        return str.getBytes("UTF-8");
    }

    private static Cipher getCipher(int i) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher instance = Cipher.getInstance("AES/CBC/PKCS5Padding");
        instance.init(i, generateKey(), generateIv());
        return instance;
    }

    public static String encryptAndEncode(String str) {
        try {
            return Base64.encodeToString(getCipher(1).doFinal(getBytes(str)), 2);
        } catch (Throwable th) {
            throw new RuntimeException(th);
        }
    }

    public static String decryptAndDecode(String str){
        try {
            return new String(Base64.decode(getCipher(1).doFinal(getBytes(str)),2), StandardCharsets.UTF_8);
        } catch (Exception th) {
            return String.valueOf(th);
        }
    }

    @SuppressLint("LongLogTag")
   public static void printpass() {
        KeyPair keyPair = getKeyPair();
        String key1 = new String(Base64.encodeToString(keyPair.getPublic().getEncoded(), 2));
        String key2 = new String(Base64.encodeToString(keyPair.getPrivate().getEncoded(), 2));
        Log.i("AES_example public", encryptAndEncode(key1));
        Log.i("AES_example public without encryption", key1);
        Log.i("AES_example private", encryptAndEncode(key2));
        Log.i("AES_example decode", decryptAndDecode(encryptAndEncode(key2)));
        Log.i("AES_example private without encryption", key2);
        String encryptRSAToString = encryptRSAToString("my name is mohit singh", key1);
        Log.i("encryptRSAToString", encryptRSAToString);
    }

    public static String encryptRSAToString(String str, String str2) {
        String str3;
        try {
            PublicKey generatePublic = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Base64.decode(str2.trim().getBytes(), 0)));
            Cipher instance = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-1ANDMGF1PADDING");
            instance.init(1, generatePublic);
            str3 = new String(Base64.encodeToString(instance.doFinal(str.getBytes("UTF-8")), 2));
        } catch (Exception e) {
            e.printStackTrace();
            str3 = "";
        }
        return str3.replaceAll("(\\r|\\n)", "");
    }
}
