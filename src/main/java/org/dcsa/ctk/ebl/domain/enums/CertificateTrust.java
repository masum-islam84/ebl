package org.dcsa.ctk.ebl.domain.enums;

import java.util.Arrays;

public enum CertificateTrust {
    SIGNED("signed"),
    UNSIGNED("unsigned"),
    UNKNOWN("Unknown");

    private String name;

    CertificateTrust(String value) {
        this.name = value;
    }

    public static CertificateTrust fromValue(String value) {
        for (CertificateTrust uploadType : values()) {
            if (uploadType.name.equalsIgnoreCase(value)) {
                return uploadType;
            }
        }
        throw new IllegalArgumentException(
                "Unknown enum type " + value + ", Allowed values are " + Arrays.toString(values()));
    }
}
