package org.cloudfoundry.identity.uaa.mfa_provider;

import java.util.List;

public class UserGoogleMfaCredentials {
    private String userId;
    private String secretKey;
    private List<Integer> scratchCodes;
    private int validationCode;


    public UserGoogleMfaCredentials(String userId, String secretKey, int validationCode, List<Integer> scratchCodes) {
        this.userId = userId;
        this.secretKey = secretKey;
        this.scratchCodes = scratchCodes;
        this.validationCode = validationCode;
    }


    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public List<Integer> getScratchCodes() {
        return scratchCodes;
    }

    public void setScratchCodes(List<Integer> scratchCodes) {
        this.scratchCodes = scratchCodes;
    }

    public int getValidationCode() {
        return validationCode;
    }

    public void setValidationCode(int validationCode) {
        this.validationCode = validationCode;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        UserGoogleMfaCredentials that = (UserGoogleMfaCredentials) o;

        if (validationCode != that.validationCode) return false;
        if (!userId.equals(that.userId)) return false;
        if (!secretKey.equals(that.secretKey)) return false;
        return scratchCodes.equals(that.scratchCodes);
    }

    @Override
    public int hashCode() {
        int result = userId.hashCode();
        result = 31 * result + secretKey.hashCode();
        result = 31 * result + scratchCodes.hashCode();
        result = 31 * result + validationCode;
        return result;
    }
}
