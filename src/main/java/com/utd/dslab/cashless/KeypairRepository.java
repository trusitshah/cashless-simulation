package com.utd.dslab.cashless;

import java.security.KeyPair;
import java.util.HashMap;

public class KeypairRepository {

    private static HashMap<String, KeyPair> keypairs;

    public static void addKeypair(String paymentGatewayId, KeyPair keyPair) {
        keypairs.put(paymentGatewayId, keyPair);
    }

    public static KeyPair getKeyPair(String paymentGatewayId) {
        return keypairs.get(paymentGatewayId);
    }

    @Override
    public String toString() {
        return "com.utd.dslab.cashless.KeypairRepository{" +
                "keypairs=" + keypairs +
                '}';
    }
}
