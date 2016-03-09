/*******************************************************************************
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

package org.cloudfoundry.identity.uaa.provider;

import java.net.URL;

public class OauthIdentityProviderDefinition extends ExternalIdentityProviderDefinition {
    private URL authUrl;
    private URL tokenUrl;
    private URL tokenKeyUrl;
    private String tokenKey;
    private String alias;
    private String linkText;
    private boolean showLinkText = true;
    private boolean skipSslValidation;
    private String relyingPartyId;
    private String relyingPartySecret;

    public URL getAuthUrl() {
        return authUrl;
    }

    public void setAuthUrl(URL authUrl) {
        this.authUrl = authUrl;
    }

    public URL getTokenUrl() {
        return tokenUrl;
    }

    public void setTokenUrl(URL tokenUrl) {
        this.tokenUrl = tokenUrl;
    }

    public URL getTokenKeyUrl() {
        return tokenKeyUrl;
    }

    public void setTokenKeyUrl(URL tokenKeyUrl) {
        this.tokenKeyUrl = tokenKeyUrl;
    }

    public String getTokenKey() {
        return tokenKey;
    }

    public void setTokenKey(String tokenKey) {
        this.tokenKey = tokenKey;
    }

    public String getAlias() {
        return alias;
    }

    public void setAlias(String alias) {
        this.alias = alias;
    }

    public String getLinkText() {
        return linkText;
    }

    public void setLinkText(String linkText) {
        this.linkText = linkText;
    }

    public boolean isShowLinkText() {
        return showLinkText;
    }

    public void setShowLinkText(boolean showLinkText) {
        this.showLinkText = showLinkText;
    }

    public String getRelyingPartyId() {
        return relyingPartyId;
    }

    public void setRelyingPartyId(String relyingPartyId) {
        this.relyingPartyId = relyingPartyId;
    }

    public String getRelyingPartySecret() {
        return relyingPartySecret;
    }

    public void setRelyingPartySecret(String relyingPartySecret) {
        this.relyingPartySecret = relyingPartySecret;
    }

    public boolean isSkipSslValidation() {
        return skipSslValidation;
    }

    public void setSkipSslValidation(boolean skipSslValidation) {
        this.skipSslValidation = skipSslValidation;
    }
}
