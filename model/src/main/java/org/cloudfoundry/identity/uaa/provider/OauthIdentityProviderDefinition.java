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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.net.URL;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OauthIdentityProviderDefinition extends ExternalIdentityProviderDefinition {
    private URL authUrl;
    private URL tokenUrl;
    private URL tokenKeyUrl;
    private URL userInfoUrl;
    private String tokenKey;
    private String linkText;
    private boolean showLinkText = true;
    private boolean skipSslValidation;
    private String relyingPartyId;
    private String relyingPartySecret;


    public URL getAuthUrl() {
        return authUrl;
    }

    public OauthIdentityProviderDefinition setAuthUrl(URL authUrl) {
        this.authUrl = authUrl;
        return this;
    }

    public URL getTokenUrl() {
        return tokenUrl;
    }

    public OauthIdentityProviderDefinition setTokenUrl(URL tokenUrl) {
        this.tokenUrl = tokenUrl;
        return this;
    }

    public URL getTokenKeyUrl() {
        return tokenKeyUrl;
    }

    public OauthIdentityProviderDefinition setTokenKeyUrl(URL tokenKeyUrl) {
        this.tokenKeyUrl = tokenKeyUrl;
        return this;
    }

    public String getTokenKey() {
        return tokenKey;
    }

    public OauthIdentityProviderDefinition setTokenKey(String tokenKey) {
        this.tokenKey = tokenKey;
        return this;
    }

    public String getLinkText() {
        return linkText;
    }

    public OauthIdentityProviderDefinition setLinkText(String linkText) {
        this.linkText = linkText;
        return this;
    }

    public boolean isShowLinkText() {
        return showLinkText;
    }

    public OauthIdentityProviderDefinition setShowLinkText(boolean showLinkText) {
        this.showLinkText = showLinkText;
        return this;
    }

    public String getRelyingPartyId() {
        return relyingPartyId;
    }

    public OauthIdentityProviderDefinition setRelyingPartyId(String relyingPartyId) {
        this.relyingPartyId = relyingPartyId;
        return this;
    }

    public String getRelyingPartySecret() {
        return relyingPartySecret;
    }

    public OauthIdentityProviderDefinition setRelyingPartySecret(String relyingPartySecret) {
        this.relyingPartySecret = relyingPartySecret;
        return this;
    }

    public boolean isSkipSslValidation() {
        return skipSslValidation;
    }

    public OauthIdentityProviderDefinition setSkipSslValidation(boolean skipSslValidation) {
        this.skipSslValidation = skipSslValidation;
        return this;
    }

    public URL getUserInfoUrl() {
        return userInfoUrl;
    }

    public OauthIdentityProviderDefinition setUserInfoUrl(URL userInfoUrl) {
        this.userInfoUrl = userInfoUrl;
        return this;
    }
}
