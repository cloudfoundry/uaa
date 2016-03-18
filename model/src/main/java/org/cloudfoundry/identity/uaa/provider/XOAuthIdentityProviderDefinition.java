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
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class XOAuthIdentityProviderDefinition<TAuthenticationFlow extends XOAuthIdentityProviderDefinition.AuthenticationFlow> extends ExternalIdentityProviderDefinition {
    private URL authUrl;
    private URL tokenUrl;
    private URL tokenKeyUrl;
    private String tokenKey;
    private String linkText;
    private boolean showLinkText = true;
    private boolean skipSslValidation;
    private String relyingPartyId;
    private String relyingPartySecret;
    private TAuthenticationFlow authenticationFlow;

    public TAuthenticationFlow getAuthenticationFlow() {
        return authenticationFlow;
    }

    public XOAuthIdentityProviderDefinition<TAuthenticationFlow> setAuthenticationFlow(TAuthenticationFlow authenticationFlow) {
        this.authenticationFlow = authenticationFlow;
        return this;
    }

    public URL getAuthUrl() {
        return authUrl;
    }

    public XOAuthIdentityProviderDefinition<TAuthenticationFlow> setAuthUrl(URL authUrl) {
        this.authUrl = authUrl;
        return this;
    }

    public URL getTokenUrl() {
        return tokenUrl;
    }

    public XOAuthIdentityProviderDefinition<TAuthenticationFlow> setTokenUrl(URL tokenUrl) {
        this.tokenUrl = tokenUrl;
        return this;
    }

    public URL getTokenKeyUrl() {
        return tokenKeyUrl;
    }

    public XOAuthIdentityProviderDefinition<TAuthenticationFlow> setTokenKeyUrl(URL tokenKeyUrl) {
        this.tokenKeyUrl = tokenKeyUrl;
        return this;
    }

    public String getTokenKey() {
        return tokenKey;
    }

    public XOAuthIdentityProviderDefinition<TAuthenticationFlow> setTokenKey(String tokenKey) {
        this.tokenKey = tokenKey;
        return this;
    }

    public String getLinkText() {
        return linkText;
    }

    public XOAuthIdentityProviderDefinition<TAuthenticationFlow> setLinkText(String linkText) {
        this.linkText = linkText;
        return this;
    }

    public boolean isShowLinkText() {
        return showLinkText;
    }

    public XOAuthIdentityProviderDefinition<TAuthenticationFlow> setShowLinkText(boolean showLinkText) {
        this.showLinkText = showLinkText;
        return this;
    }

    public String getRelyingPartyId() {
        return relyingPartyId;
    }

    public XOAuthIdentityProviderDefinition<TAuthenticationFlow> setRelyingPartyId(String relyingPartyId) {
        this.relyingPartyId = relyingPartyId;
        return this;
    }

    public String getRelyingPartySecret() {
        return relyingPartySecret;
    }

    public XOAuthIdentityProviderDefinition<TAuthenticationFlow> setRelyingPartySecret(String relyingPartySecret) {
        this.relyingPartySecret = relyingPartySecret;
        return this;
    }

    public boolean isSkipSslValidation() {
        return skipSslValidation;
    }

    public XOAuthIdentityProviderDefinition<TAuthenticationFlow> setSkipSslValidation(boolean skipSslValidation) {
        this.skipSslValidation = skipSslValidation;
        return this;
    }

    public interface AuthenticationFlow {
        String getType();

        String getResponseType();

        String getTokenFromResponse(Map<String, String> responseBody);

    }
}
