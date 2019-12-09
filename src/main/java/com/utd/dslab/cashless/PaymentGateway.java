package com.utd.dslab.cashless;

import com.utd.dslab.cashless.exceptions.CashlessException;
import com.utd.dslab.cashless.security.SHA256;
import com.utd.dslab.cashless.transaction.ECCSign;
import com.utd.dslab.cashless.transaction.ECCVerify;
import com.utd.dslab.cashless.transaction.PlainTransaction;
import com.utd.dslab.cashless.transaction.TransactionManager;

import java.security.*;

public class PaymentGateway {

    /**
     * PaymentGatewayType:
     * ADD: Adds money to the card.
     * PURCHASE: Makes purchase using the card.
     * BOTH: Can add money and make purchases.
     * SERVER: com.utd.dslab.cashless.PaymentGateway at card manufacturing site. It is used to create the initial com.utd.dslab.cashless.transaction.
     */
    public enum type {
        ADD, PURCHASE, BOTH, SERVER
    }

    /**
     * Transaction Type
     */
    public enum TransactionType {
        ADD, PURCHASE
    }

    /**
     * Unique id of a payment gateway. It is 4 byte long. Represented using a 8 char long hex string.
     */
    private String uniqueId;

    /**
     * Name of the payment gateway.
     */
    private String name;

    /**
     * payment gateway type.
     * @See tpye
     */
    private type type;

    /**
     * keypair used for the com.utd.dslab.cashless.transaction.
     */
    private KeyPair keyPair;

    /**
     * indicates whether the payment gateway is connected to the server or not.
     */
    private boolean isOnline;

    /**
     *
     * @param uniqueId
     * @param name
     * @param type
     * @param keyPair
     */
    public PaymentGateway(String uniqueId, String name, PaymentGateway.type type, KeyPair keyPair) {
        this.uniqueId = uniqueId;
        this.name = name;
        this.type = type;
        this.keyPair = keyPair;
        this.isOnline = true;
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
    public String getName() {
        return name;
    }

    /**
     *
     * @return
     */
    public PaymentGateway.type getType() {
        return type;
    }

    /**
     *
     * @return
     */
    public KeyPair getKeyPair() {
        return keyPair;
    }

    /**
     *
     * @return
     */
    public boolean isOnline() {
        return isOnline;
    }

    /**
     *
     * @param online
     */
    public void setOnline(boolean online) {
        isOnline = online;
    }

    /**
     * performs the com.utd.dslab.cashless.transaction and overwrites the previous com.utd.dslab.cashless.transaction on the card.
     *
     * @param card card performing the com.utd.dslab.cashless.transaction.
     * @param amount amount involved in the com.utd.dslab.cashless.transaction.
     * @param transactionType type of the com.utd.dslab.cashless.transaction. If purchase reduces the amount in the card, else increases the amount.
     *
     * @throws GeneralSecurityException
     * @throws CashlessException
     */
    public void performTransaction(Card card, double amount, TransactionType transactionType) throws GeneralSecurityException, CashlessException {
        String prevTransactionPaymentGateway = card.getPaymentGatewayId();
        PublicKey prevTransactionPublicKey = KeypairRepository.getKeyPair(prevTransactionPaymentGateway).getPublic();
        PlainTransaction prevTransaction = TransactionManager.verifyAndDecrypt(card.getTransaction(), ECCVerify.getInstance(prevTransactionPublicKey));

        byte[] hashkey = new byte[8];
        new SecureRandom().nextBytes(hashkey);

        double newAmount;
        if(transactionType == TransactionType.ADD) {
            newAmount = prevTransaction.getAmount() + amount;
        } else {
            newAmount = prevTransaction.getAmount() - amount;
        }

        if(newAmount < TransactionManager.MIN_AMOUNT) {
            throw new CashlessException("Insufficient money in the card!");
        } else if (newAmount > TransactionManager.MAX_AMOUNT){
            throw new CashlessException("com.utd.dslab.cashless.Card can not have amount more than " + TransactionManager.MAX_AMOUNT);
        }

        new SecureRandom().nextBytes(hashkey);
        String passcode = card.getPasscode();
        byte[] passcodeHash = SHA256.getHMAC(passcode, hashkey);

        PlainTransaction transaction = new PlainTransaction(uniqueId, card.getUniqueId(), newAmount, passcodeHash, hashkey, System.currentTimeMillis(), (short) (prevTransaction.getSequenceNumber() + 1));
        PrivateKey transactionPrivateKey = KeypairRepository.getKeyPair(uniqueId).getPrivate();

        byte[] transactionBytes = TransactionManager.encryptAndSignTransaction(transaction,ECCSign.getInstance(transactionPrivateKey));

        card.setTransaction(transactionBytes, uniqueId);
    }

    @Override
    public String toString() {
        return "com.utd.dslab.cashless.PaymentGateway{" +
                "uniqueId='" + uniqueId + '\'' +
                ", name='" + name + '\'' +
                ", type=" + type +
                ", keyPair=" + keyPair +
                ", isOnline=" + isOnline +
                '}';
    }
}
