package com.utd.dslab.cashless;

import com.utd.dslab.cashless.card.Card;
import com.utd.dslab.cashless.card.CardManager;
import com.utd.dslab.cashless.gateway.KeypairRepository;
import com.utd.dslab.cashless.gateway.PaymentGateway;
import com.utd.dslab.cashless.gateway.PaymentGatewayManager;
import com.utd.dslab.cashless.transaction.ECCVerify;
import com.utd.dslab.cashless.transaction.TransactionManager;

public class Main {

    public static void main(String[] args) {
        System.out.println("This is simulation for the cashless payment system!!");

        try {
            PaymentGateway server = PaymentGatewayManager.createServerPaymentGateway();
            PaymentGateway addMachine = PaymentGatewayManager.createAddPaymentGateway();
            PaymentGateway vendingMachine = PaymentGatewayManager.createPurchasePaymentGateway();

            Card card1 = CardManager.createCard(server);
            addMachine.performTransaction(card1, 100, PaymentGateway.TransactionType.ADD);
            vendingMachine.performTransaction(card1, 5, PaymentGateway.TransactionType.PURCHASE);

            System.out.println(TransactionManager.verifyAndDecrypt(card1.getTransaction(), ECCVerify.getInstance(KeypairRepository.getKeyPair(card1.getPaymentGatewayId()).getPublic())));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }
}
