package com.utd.dslab.cashless;

import com.utd.dslab.cashless.exceptions.CashlessException;

import java.security.GeneralSecurityException;

public class CardManager {

    private static int sequenceNumber = 1;

    public static Card createCard(PaymentGateway paymentGateway) throws CashlessException, GeneralSecurityException {
        return Card.createCard(String.format("%016x",sequenceNumber++), paymentGateway);
    }
}
