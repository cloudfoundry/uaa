/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mfa;

import java.io.Serializable;
import java.util.List;

public class UserGoogleMfaCredentials implements Serializable {
    private String userId;
    private String secretKey;
    private List<Integer> scratchCodes;
    private int validationCode;
    private String mfaProviderId;
    private String ZoneId;


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

    public String getMfaProviderId() {
        return mfaProviderId;
    }

    public String getZoneId() {
        return ZoneId;
    }

    public UserGoogleMfaCredentials setZoneId(String zoneId) {
        ZoneId = zoneId;
        return this;
    }

    public UserGoogleMfaCredentials setMfaProviderId(String mfaProviderId) {
        this.mfaProviderId = mfaProviderId;
        return this;
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
