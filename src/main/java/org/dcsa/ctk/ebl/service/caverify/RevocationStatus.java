package org.dcsa.ctk.ebl.service.caverify;

public enum RevocationStatus {

    GOOD("Good"), UNKNOWN("Unknown"), REVOKED("Revoked");
    private String message;

    private RevocationStatus(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
