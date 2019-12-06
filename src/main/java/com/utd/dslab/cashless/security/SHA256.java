package com.utd.dslab.cashless.security;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * class for SHA 256 hashing.
 */
public class SHA256 {

    /**
     * generates SHA 256 hash of a messasge.
     * @param message
     * @return
     */
    public static byte[] getMessageDigest(String message){
        return getMessageDigest(message.getBytes());
    }

    /**
     * generates HMAC of a message using the secret.
     * @param message
     * @param secret
     * @return
     */
    public static byte[] getHMAC(String message,byte[] secret){
        return getHMAC(message.getBytes(), secret);
    }

    /**
     * generate SHA 256 of a message.
     * @param message
     * @return
     */
    public static byte[] getMessageDigest(byte[] message){

        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
            md.update(message);

            return md.digest();
        } catch (NoSuchAlgorithmException e) {

            e.printStackTrace();
        }

        return null;
    }

    /**
     * generate HMAC of a message using a secret.
     * @param message
     * @param secret
     * @return
     */
    public static byte[] getHMAC(byte[] message,byte[] secret){

        Mac sha256_HMAC;
        try {
            sha256_HMAC = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret_key = new SecretKeySpec(secret, "HmacSHA256");
            sha256_HMAC.init(secret_key);
            return sha256_HMAC.doFinal(message);

        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        }

        return null;
    }

}
