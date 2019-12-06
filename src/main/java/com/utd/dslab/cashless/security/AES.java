package com.utd.dslab.cashless.security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * Class for AES utilities.
 */
public class AES {

    /**
     * encrypt plainttext using key.
     * The encryption mode is AES/CBC with PKCS5 padding.
     *
     * @param key
     * @param iv
     * @param plainText
     * @return
     */
    public static byte[] encrypt(byte[] key,byte[] iv, byte[] plainText){

        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, generateKey(key),new IvParameterSpec(iv));
            return cipher.doFinal(plainText);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * decrypt ciphertext to plain text.
     * The encryption mode is AES/CBC with PKCS5 padding.
     *
     * @param key
     * @param iv
     * @param ciphertext
     * @return
     */
    public static byte[] decrypt(byte[] key,byte[] iv, byte[] ciphertext){

        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, generateKey(key),new IvParameterSpec(iv));
            return cipher.doFinal(ciphertext);

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * utility function to generate a random IV.
     * the size of IV is 16 bytes, which is standard as per the NIST AES protocol.
     * @return
     */
    public static byte[] generateRandomIV(){

        SecureRandom secureRandom = new SecureRandom();

        byte [] iv = new byte[16];

        secureRandom.nextBytes(iv);

        return iv;
    }

    /**
     * Generate random AES key for 128 bit encryption.
     *
     * @return
     */
    public static byte[] generateRandomAESKey(){
        SecureRandom secureRandom = new SecureRandom();

        byte[] key = new byte[16];

        secureRandom.nextBytes(key);

        return key;
    }

    /**
     * generates key object from a byte array.
     * @param keyBytes
     * @return
     */
    private static Key generateKey(byte[] keyBytes){

        return new SecretKeySpec(keyBytes, "AES");

    }

}