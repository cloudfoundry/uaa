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

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.ParameterizedType;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class AbstractXOAuthIdentityProviderDefinition<T extends AbstractXOAuthIdentityProviderDefinition> extends ExternalIdentityProviderDefinition {
    private URL authUrl;
    private URL tokenUrl;
    private URL tokenKeyUrl;
    private String tokenKey;
    private String linkText;
    private boolean showLinkText = true;
    private boolean skipSslValidation;
    private String relyingPartyId;
    private String relyingPartySecret;
    private List<String> scopes;
    private String issuer;
    private String responseType = "code";

    public URL getAuthUrl() {
        return authUrl;
    }

    public T setAuthUrl(URL authUrl) {
        this.authUrl = authUrl;
        return (T) this;
    }

    public URL getTokenUrl() {
        return tokenUrl;
    }

    public T setTokenUrl(URL tokenUrl) {
        this.tokenUrl = tokenUrl;
        return (T) this;
    }

    public URL getTokenKeyUrl() {
        return tokenKeyUrl;
    }

    public T setTokenKeyUrl(URL tokenKeyUrl) {
        this.tokenKeyUrl = tokenKeyUrl;
        return (T) this;
    }

    public String getTokenKey() {
        return tokenKey;
    }

    public T setTokenKey(String tokenKey) {
        this.tokenKey = tokenKey;
        return (T) this;
    }

    public String getLinkText() {
        return linkText;
    }

    public T setLinkText(String linkText) {
        this.linkText = linkText;
        return (T) this;
    }

    public boolean isShowLinkText() {
        return showLinkText;
    }

    public T setShowLinkText(boolean showLinkText) {
        this.showLinkText = showLinkText;
        return (T) this;
    }

    public String getRelyingPartyId() {
        return relyingPartyId;
    }

    public T setRelyingPartyId(String relyingPartyId) {
        this.relyingPartyId = relyingPartyId;
        return (T) this;
    }

    public String getRelyingPartySecret() {
        return relyingPartySecret;
    }

    public T setRelyingPartySecret(String relyingPartySecret) {
        this.relyingPartySecret = relyingPartySecret;
        return (T) this;
    }

    public boolean isSkipSslValidation() {
        return skipSslValidation;
    }

    public T setSkipSslValidation(boolean skipSslValidation) {
        this.skipSslValidation = skipSslValidation;
        return (T) this;
    }

    public List<String> getScopes() {
        return scopes;
    }

    public T setScopes(List<String> scopes) {
        this.scopes = scopes;
        return (T) this;
    }

    public String getIssuer() {
        return issuer;
    }

    public T setIssuer(String issuer) {
        this.issuer = issuer;
        return (T) this;
    }

    public String getResponseType() {
        return responseType;
    }

    public T setResponseType(String responseType) {
        this.responseType = responseType;
        return (T) this;
    }

    @JsonIgnore
    public Class getParameterizedClass() {
        ParameterizedType parameterizedType =
            (ParameterizedType)getClass().getGenericSuperclass();
        return (Class) parameterizedType.getActualTypeArguments()[0];
    }

    @JsonIgnore
    public String getCompleteAuthorizationURI(String baseURL, String alias) throws UnsupportedEncodingException {
        String authUrlBase = getAuthUrl().toString();
        String queryAppendDelimiter = authUrlBase.contains("?") ? "&" : "?";
        List<String> query = new ArrayList<>();
        query.add("client_id=" + getRelyingPartyId());
        query.add("response_type="+ URLEncoder.encode(getResponseType(), "UTF-8"));
        query.add("redirect_uri=" + URLEncoder.encode(baseURL + "/login/callback/" + alias, "UTF-8"));
        if (getScopes() != null && !getScopes().isEmpty()) {
            query.add("scope=" + URLEncoder.encode(String.join(" ", getScopes()), "UTF-8"));
        }
        if (OIDCIdentityProviderDefinition.class.equals(getParameterizedClass())) {
            final RandomValueStringGenerator nonceGenerator = new RandomValueStringGenerator(12);
            query.add("nonce=" + nonceGenerator.generate());
        }
        String queryString = String.join("&", query);
        return authUrlBase + queryAppendDelimiter + queryString;
    }
}
