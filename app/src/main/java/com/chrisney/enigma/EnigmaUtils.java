package com.chrisney.enigma;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

public class EnigmaUtils {
   private final static int[] data = {112, 53, 77, 90, 76, 73, 112, 115, 82, 71, 103, 72, 73, 36, 76, 108, 50, 85, 78, 105, 110, 104, 105, 72, 109, 88, 122, 117, 102, 67, 79, 68};
   public static String enigmatization(byte[] enc) {
        try {
            byte[] keyValue  = keyToBytes(data);
            byte[] result = decrypt(keyValue, enc);
            return new String(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    private static byte[] decrypt(byte[] keyValue, byte[] encrypted)
            throws Exception {
        SecretKey skeySpec = new SecretKeySpec(keyValue, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[cipher.getBlockSize()];
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParams);
        return cipher.doFinal(encrypted);
    }
    private static byte[] keyToBytes(int[] key) {
        int size = 16 * (key.length / 16);
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < size; i++) {
            builder.append((char) key[i]);
        }
        return builder.toString().getBytes();
    }
}
