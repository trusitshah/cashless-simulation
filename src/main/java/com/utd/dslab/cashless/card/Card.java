package com.utd.dslab.cashless.card;

import com.utd.dslab.cashless.gateway.KeypairRepository;
import com.utd.dslab.cashless.gateway.PaymentGateway;
import com.utd.dslab.cashless.exceptions.CashlessException;
import com.utd.dslab.cashless.security.SHA256;
import com.utd.dslab.cashless.transaction.ECCSign;
import com.utd.dslab.cashless.transaction.ECCVerify;
import com.utd.dslab.cashless.transaction.PlainTransaction;
import com.utd.dslab.cashless.transaction.TransactionManager;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

public class Card {

    /**
     * unique id of the card.
     */
    private String uniqueId;

    /**
     * Transaction stored inside the card.
     * This com.utd.dslab.cashless.transaction is encrypted using a master key and signed by payment gateway.
     */
    private byte[] transaction;

    /**
     * Payment gateway id of the com.utd.dslab.cashless.transaction to retrieve the public key of the com.utd.dslab.cashless.transaction.
     */
    private String paymentGatewayId;

    /**
     * passcode for the card.
     */
    private String passcode;

    /**
     *
     *
     * @param uniqueId
     * @param transaction
     * @param paymentGatewayId
     */
    private Card(String uniqueId, byte[] transaction, String paymentGatewayId, String passcode) {
        this.uniqueId = uniqueId;
        this.transaction = transaction;
        this.paymentGatewayId = paymentGatewayId;
        this.passcode = passcode;
    }

    /**
     * Creates a new card and initialize it with the first com.utd.dslab.cashless.transaction with 0 amount.
     *
     * @param uniqueId
     * @param paymentGateway
     * @return newly created card.
     * @throws CashlessException If the payment gateway type is not server, a cashless exception will be raised.
     * @throws GeneralSecurityException This error occurs when there is an issue in writing initial value to the card.
     */

    public static Card createCard(String uniqueId, PaymentGateway paymentGateway) throws CashlessException, GeneralSecurityException {
        if(paymentGateway.getType() != PaymentGateway.type.SERVER) {
            throw new CashlessException("A card cannot be created using a payment gateway of type " + paymentGateway.getType());
        }

        byte[] hashkey = new byte[8];
        new SecureRandom().nextBytes(hashkey);
        String passcode = generateRandomPasscode();
        byte[] passcodeHash = SHA256.getHMAC(passcode, hashkey);
        PlainTransaction plainTransaction = new PlainTransaction(paymentGateway.getUniqueId(), uniqueId, 0, passcodeHash, hashkey, System.currentTimeMillis(), (short) (1));
        return new Card(uniqueId, TransactionManager.encryptAndSignTransaction(plainTransaction, ECCSign.getInstance(KeypairRepository.getKeyPair(paymentGateway.getUniqueId()).getPrivate())), paymentGateway.getUniqueId(), passcode);
    }

    /**
     *
     * @return
     */
    public String getUniqueId() {
        return uniqueId;
    }

    /**
     *
     * @return
     */
    public byte[] getTransaction() {
        return transaction;
    }

    /**
     * It has two parameters to ensure that the paymentGatewayId is the same as the paymentGatewayId inside the com.utd.dslab.cashless.transaction.
     *
     * @param transaction
     * @param paymentGatewayId
     * @throws GeneralSecurityException
     * @throws CashlessException In case the paymentGatewayId doesn't match with the paymentGatewayId inside the com.utd.dslab.cashless.transaction.
     */
    public void setTransaction(byte[] transaction, String paymentGatewayId) throws GeneralSecurityException, CashlessException {
        PlainTransaction plainTransaction = TransactionManager.verifyAndDecrypt(transaction, ECCVerify.getInstance(KeypairRepository.getKeyPair(paymentGatewayId).getPublic()));

        if(plainTransaction.getVmId().equals(paymentGatewayId)) {
            this.paymentGatewayId = paymentGatewayId;
            this.transaction = transaction;
        } else {
            throw new CashlessException("Payment gateway id mismatch!");
        }
    }

    /**
     *
     * @return
     */
    public String getPaymentGatewayId() {
        return paymentGatewayId;
    }

    /**
     *
     * @return
     */
    public String getPasscode() {
        return passcode;
    }

    /**
     *
     * @return
     */
    private static String generateRandomPasscode() {
        Random random = new Random();

        return Double.toString(random.nextDouble() * 8999.0 + 1000.0);
    }

    @Override
    public String toString() {
        return "com.utd.dslab.cashless.card.Card{" +
                "uniqueId='" + uniqueId + '\'' +
                ", com.utd.dslab.cashless.transaction=" + Arrays.toString(transaction) +
                ", paymentGatewayId='" + paymentGatewayId + '\'' +
                '}';
    }
}
