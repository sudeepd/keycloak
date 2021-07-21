package org.keycloak.common;

import org.bouncycastle.crypto.CryptoServicesRegistrar;

public class FipsApprovedMode {
    private static final String FIPS_MODE_INDICATOR = "org.bouncycastle.fips.approved_only";
    private static final int MIN_PBKDF_PASSWORD_LENGTH = 14;

    public static String pbkdfPad(String raw) {
        // In fips mode, the pbkdf function does not allow less than 14 characters.
        // During login, the user provided value needs to be hashed, and the password hashing fails
        // because of this functionality of the pbkdf fucntion.
        // As a workaround, we pad smaller inputs with nulls to ensure that a raw value is always at least
        // 14 characters.
        if ( CryptoServicesRegistrar.isInApprovedOnlyMode() && raw.length() < MIN_PBKDF_PASSWORD_LENGTH) {
            int nPad = MIN_PBKDF_PASSWORD_LENGTH - raw.length();
            String result = raw;
            for (int i = 0 ; i < nPad; i++) result += "\0";
            return result;
        }else
            return raw;
    }
}
