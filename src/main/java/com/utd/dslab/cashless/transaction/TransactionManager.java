package com.utd.dslab.cashless.transaction;

import com.utd.dslab.cashless.security.AES;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * manages encryption and signing of a single com.utd.dslab.cashless.transaction.
 */
public class TransactionManager {

    private static final byte[] aesKey = DatatypeConverter.parseHexBinary("2b7e151628aed2a6abf7158809cf4f3c");

    public static final double MAX_AMOUNT = 100;
    public static final double MIN_AMOUNT = 0;

    /**
     * encrypts the com.utd.dslab.cashless.transaction and sign it.
     * @param transaction
     * @param eccSign
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static byte[] encryptAndSignTransaction(PlainTransaction transaction, ECCSign eccSign) throws GeneralSecurityException {

        byte[] transcationBytes = transaction.getBytes();
        byte[] iv = AES.generateRandomIV();
        byte[] encryption = AES.encrypt(aesKey,iv,transcationBytes);
        byte[] signature = eccSign.sign(encryption);

        ByteBuffer buffer = ByteBuffer.allocate(encryption.length + signature.length + iv.length + 2);

        buffer.put((byte)encryption.length).put((byte) signature.length).put(encryption).put(signature).put(iv);

        return buffer.array();

    }

    /**
     * verifies the signed com.utd.dslab.cashless.transaction and decrypts it.
     * @param transactionBytes
     * @param eccVerify
     * @return
     * @throws GeneralSecurityException
     */
    public static PlainTransaction verifyAndDecrypt(byte[] transactionBytes, ECCVerify eccVerify) throws GeneralSecurityException {

        int encryptionSize = transactionBytes[0];
        int signatureSize = transactionBytes[1];
        byte[] encryptionBytes = Arrays.copyOfRange(transactionBytes,2,2 + encryptionSize);
        byte[] signatureBytes = Arrays.copyOfRange(transactionBytes,2 + encryptionSize, 2 + encryptionSize + signatureSize);
        byte[] iv = Arrays.copyOfRange(transactionBytes, 2 + encryptionSize + signatureSize, 2 + encryptionSize + signatureSize + 16);

        boolean verification = eccVerify.verify(encryptionBytes,signatureBytes);

        if(!verification) {
            return null;
        }

        byte[] plainTransactionBytes = AES.decrypt(aesKey,iv,encryptionBytes);

        return PlainTransaction.parse(plainTransactionBytes);
    }




}
