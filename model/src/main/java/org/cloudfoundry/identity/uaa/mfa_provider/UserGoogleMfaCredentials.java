package org.cloudfoundry.identity.uaa.mfa_provider;

import java.util.List;

public class UserGoogleMfaCredentials {
    private String userId;
    private String secretKey;
    private boolean active;
    private List<Integer> scratchCodes;
    private int validationCode;

    public UserGoogleMfaCredentials(String userId, String secretKey, int validationCode, List<Integer> scratchCodes) {
        this(userId, secretKey, validationCode, scratchCodes, false);
    }

    public UserGoogleMfaCredentials(String userId, String secretKey, int validationCode, List<Integer> scratchCodes, boolean active) {
        this.userId = userId;
        this.secretKey = secretKey;
        this.scratchCodes = scratchCodes;
        this.validationCode = validationCode;
        this.active = active;
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

    public boolean isActive() {
        return active;
    }

    public void setActive(boolean active) {
        this.active = active;
    }
}
