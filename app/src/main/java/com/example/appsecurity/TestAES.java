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
import com.chrisney.enigma.EnigmaUtils;

public class TestAES {

    private static String PASSWORD = EnigmaUtils.enigmatization(new byte[]{76, -6, -117, -21, 125, -94, -16, 125, 118, 53, 94, 3, -119, -25, 126, -80});
    private static String SALT = EnigmaUtils.enigmatization(new byte[]{112, -19, 36, -106, 49, -87, -30, -73, -65, -86, -115, -67, -124, 36, 112, -124});

    public static final String KUODDLFDZB = "nrrihR2ff*0oI5fP*ESzP9M";

    public static IvParameterSpec generateIv() {
        if (KUODDLFDZB.isEmpty()) KUODDLFDZB.getClass().toString();
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static KeyPair getKeyPair() {
        try {
            KeyPairGenerator instance = KeyPairGenerator.getInstance(EnigmaUtils.enigmatization(new byte[]{-99, -115, -90, 98, -101, 123, -57, -41, 2, -41, -9, 6, -27, 107, 95, -120}));
            instance.initialize(4096);
            return instance.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }


    private static Key generateKey() throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException {
        return new SecretKeySpec(SecretKeyFactory.getInstance(EnigmaUtils.enigmatization(new byte[]{-36, 35, -35, 18, 101, -49, -90, 61, 105, 126, -116, -12, 117, 48, 1, 97, -121, 29, 35, -28, -53, 33, 13, -86, 13, -22, 68, -82, 106, 74, 124, -26}))
                .generateSecret(new PBEKeySpec(PASSWORD.toCharArray(), getBytes(SALT), 65536, 128)).getEncoded(), EnigmaUtils.enigmatization(new byte[]{-39, 101, -80, -2, -100, 12, 34, -38, 9, -59, 64, -101, -90, 33, 53, 15}));
    }

    private static byte[] getBytes(String str) throws UnsupportedEncodingException {
        return str.getBytes(EnigmaUtils.enigmatization(new byte[]{-29, 112, 61, -116, 81, 81, 127, 35, 54, 75, -72, 29, -68, -34, -113, -125}));
    }

    private static Cipher getCipher(int i) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher instance = Cipher.getInstance(EnigmaUtils.enigmatization(new byte[]{-47, -71, -17, -19, 110, 109, 18, 103, -68, 56, -7, 36, -39, -116, -65, -102, 101, 43, 62, -98, 29, 30, -71, 76, 83, 124, 10, 15, 91, -103, -27, 122}));
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
        Log.i(EnigmaUtils.enigmatization(new byte[]{69, 46, 127, 37, 46, 97, 25, -36, 97, -72, 111, -91, -68, 45, -22, -121, -99, -125, -49, 42, 115, -81, 91, -8, -10, -67, 121, 6, 68, 3, -89, -18}), encryptAndEncode(key1));
        Log.i(EnigmaUtils.enigmatization(new byte[]{69, 46, 127, 37, 46, 97, 25, -36, 97, -72, 111, -91, -68, 45, -22, -121, -20, -24, -17, 20, -62, 55, 109, 39, 63, -100, -28, 18, -59, -68, 50, 124, -111, -46, 19, -43, -28, -54, 74, -29, 54, -10, 108, 124, -110, 21, 82, -111}), key1);
        Log.i(EnigmaUtils.enigmatization(new byte[]{-103, 4, 114, 65, -1, -41, 125, 26, 54, -93, 87, 0, 89, -128, 7, -89, -127, 21, -57, 110, -37, -32, -66, 41, 47, 52, 113, 45, 69, 91, 77, -128}), encryptAndEncode(key2));
        Log.i(EnigmaUtils.enigmatization(new byte[]{82, -20, -9, -47, 0, -111, -124, 49, -87, -33, -70, 43, -78, 48, 67, 46, -116, 85, -85, -96, 57, -124, 59, 104, 68, 75, 35, -21, 69, -92, 6, -37}), decryptAndDecode(encryptAndEncode(key2)));
        Log.i(EnigmaUtils.enigmatization(new byte[]{-103, 4, 114, 65, -1, -41, 125, 26, 54, -93, 87, 0, 89, -128, 7, -89, 10, -30, -9, -4, 13, -118, 79, -37, 77, -110, 119, 23, 63, -117, -32, -12, -24, 74, 26, 75, 21, -22, 14, 5, -98, 10, -128, 122, 2, 18, -49, -119}), key2);
        String encryptRSAToString = encryptRSAToString(EnigmaUtils.enigmatization(new byte[]{85, -3, -46, -96, -123, 112, 93, -73, -70, -100, -109, -25, 118, 51, -103, 91, 85, 2, -107, 112, 109, 39, 23, -119, 60, -35, -3, -68, -50, 82, 66, 57}), key1);
        Log.i(EnigmaUtils.enigmatization(new byte[]{95, -39, 80, 16, -13, 21, 116, -23, 120, 107, -127, -98, -84, -4, 55, 65, 125, -61, -10, 21, -69, 75, -117, 97, -31, -80, 27, 46, 88, -34, 109, 126}), encryptRSAToString);
    }

    public static String encryptRSAToString(String str, String str2) {
        String str3;
        try {
            PublicKey generatePublic = KeyFactory.getInstance(EnigmaUtils.enigmatization(new byte[]{-99, -115, -90, 98, -101, 123, -57, -41, 2, -41, -9, 6, -27, 107, 95, -120})).generatePublic(new X509EncodedKeySpec(Base64.decode(str2.trim().getBytes(), 0)));
            Cipher instance = Cipher.getInstance(EnigmaUtils.enigmatization(new byte[]{-49, -34, 96, 86, 11, 89, -123, 47, -59, 99, 96, -37, -43, 24, -13, 31, -21, -98, -40, 81, 13, 54, -25, -78, -92, 108, 126, 24, 100, 113, -53, -97, -73, -24, 40, 124, 66, -31, 127, -1, -37, 29, -36, -77, 83, -105, -36, -8}));
            instance.init(1, generatePublic);
            str3 = new String(Base64.encodeToString(instance.doFinal(str.getBytes(EnigmaUtils.enigmatization(new byte[]{-29, 112, 61, -116, 81, 81, 127, 35, 54, 75, -72, 29, -68, -34, -113, -125}))), 2));
        } catch (Exception e) {
            e.printStackTrace();
            str3 = EnigmaUtils.enigmatization(new byte[]{-37, -90, 95, -66, -35, 76, 80, -5, -127, 6, 53, -39, -60, 54, 41, 41});
        }
        return str3.replaceAll(EnigmaUtils.enigmatization(new byte[]{104, -124, 101, -64, 42, 46, 75, -22, -60, -77, -111, 11, 79, -17, 121, 123}), EnigmaUtils.enigmatization(new byte[]{-37, -90, 95, -66, -35, 76, 80, -5, -127, 6, 53, -39, -60, 54, 41, 41}));
    }
}
