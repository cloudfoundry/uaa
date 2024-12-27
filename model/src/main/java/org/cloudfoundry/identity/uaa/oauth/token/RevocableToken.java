/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth.token;

public class RevocableToken {

    public enum TokenType {
        ID_TOKEN, ACCESS_TOKEN, REFRESH_TOKEN
    }

    private String tokenId;
    private String clientId;
    private String userId;
    private String format;
    private TokenType responseType;
    private long issuedAt;
    private long expiresAt;
    private String scope;
    private String value;
    private String zoneId;

    public String getTokenId() {
        return tokenId;
    }

    public RevocableToken setTokenId(String tokenId) {
        this.tokenId = tokenId;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public RevocableToken setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public String getUserId() {
        return userId;
    }

    public RevocableToken setUserId(String userId) {
        this.userId = userId;
        return this;
    }

    public String getFormat() {
        return format;
    }

    public RevocableToken setFormat(String format) {
        this.format = format;
        return this;
    }

    public TokenType getResponseType() {
        return responseType;
    }

    public RevocableToken setResponseType(TokenType responseType) {
        this.responseType = responseType;
        return this;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public RevocableToken setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
        return this;
    }

    public long getExpiresAt() {
        return expiresAt;
    }

    public RevocableToken setExpiresAt(long expiresAt) {
        this.expiresAt = expiresAt;
        return this;
    }

    public String getScope() {
        return scope;
    }

    public RevocableToken setScope(String scope) {
        this.scope = scope;
        return this;
    }

    public String getValue() {
        return value;
    }

    public RevocableToken setValue(String value) {
        this.value = value;
        return this;
    }

    public String getZoneId() {
        return zoneId;
    }

    public RevocableToken setZoneId(String zoneId) {
        this.zoneId = zoneId;
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof RevocableToken)) {
            return false;
        }

        RevocableToken that = (RevocableToken) o;

        if (!getTokenId().equals(that.getTokenId())) {
            return false;
        }
        if (!getClientId().equals(that.getClientId())) {
            return false;
        }
        if (!getUserId().equals(that.getUserId())) {
            return false;
        }
        return getZoneId().equals(that.getZoneId());

    }

    @Override
    public int hashCode() {
        int result = getTokenId().hashCode();
        result = 31 * result + getClientId().hashCode();
        result = 31 * result + getUserId().hashCode();
        result = 31 * result + getZoneId().hashCode();
        return result;
    }

    @Override
    public String toString() {
        final StringBuffer sb = new StringBuffer("RevocableToken{");
        sb.append("tokenId='").append(tokenId).append('\'');
        sb.append(", clientId='").append(clientId).append('\'');
        sb.append(", userId='").append(userId).append('\'');
        sb.append(", format='").append(format).append('\'');
        sb.append(", responseType=").append(responseType);
        sb.append(", issuedAt=").append(issuedAt);
        sb.append(", expiresAt=").append(expiresAt);
        sb.append(", scope='").append(scope).append('\'');
        sb.append(", zoneId='").append(zoneId).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
