package com.utd.dslab.cashless.exceptions;

public class CashlessException extends Exception {

    public CashlessException() {
    }

    public CashlessException(String message) {
        super(message);
    }

    public CashlessException(String message, Throwable cause) {
        super(message, cause);
    }

    public CashlessException(Throwable cause) {
        super(cause);
    }

    public CashlessException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
