package org.berndpruenster.jtor.mgmt;

public class TorCtlException extends Exception {

  public TorCtlException() {
  }

  public TorCtlException(final String message) {
    super(message);
  }

  public TorCtlException(final Throwable cause) {
    super(cause);
  }

  public TorCtlException(final String message, final Throwable cause) {
    super(message, cause);
  }

  public TorCtlException(final String message, final Throwable cause, final boolean enableSuppression, final boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }

}
