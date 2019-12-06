package com.utd.dslab.cashless;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class PaymentGatewayManager {

    private static int sequenceNumber = 1;

    public static PaymentGateway createServerPaymentGateway() throws NoSuchAlgorithmException {
        return createPaymentGateway(PaymentGateway.type.SERVER);
    }

    public static PaymentGateway createAddPaymentGateway() throws NoSuchAlgorithmException {
        return createPaymentGateway(PaymentGateway.type.ADD);
    }

    public static PaymentGateway createPurchasePaymentGateway() throws NoSuchAlgorithmException {
        return createPaymentGateway(PaymentGateway.type.PURCHASE);
    }

    public static PaymentGateway createAddPurchasePaymentGateway() throws NoSuchAlgorithmException {
        return createPaymentGateway(PaymentGateway.type.BOTH);
    }

    public static PaymentGateway createPaymentGateway(PaymentGateway.type type) throws NoSuchAlgorithmException {
        KeyPair keyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();

        String uniqueId = Integer.toString(sequenceNumber++);
        PaymentGateway paymentGateway = new PaymentGateway(uniqueId, "pg_" + uniqueId, type, keyPair);

        KeypairRepository.addKeypair(uniqueId, keyPair);

        return paymentGateway;
    }
}
