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
import com.fasterxml.jackson.annotation.JsonInclude;

import java.lang.reflect.ParameterizedType;
import java.net.URL;
import java.util.List;
import java.util.Objects;

@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class AbstractExternalOAuthIdentityProviderDefinition<T extends AbstractExternalOAuthIdentityProviderDefinition> extends ExternalIdentityProviderDefinition {
    private URL authUrl;
    private URL tokenUrl;
    private URL tokenKeyUrl;
    private String tokenKey;
    private String linkText;
    private boolean showLinkText = true;
    private boolean clientAuthInBody = false;
    private boolean skipSslValidation;
    private String relyingPartyId;
    private String relyingPartySecret;
    private List<String> scopes;
    private String issuer;
    private String responseType = "code";
    private String userPropagationParameter;

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

    public boolean isClientAuthInBody() {
        return clientAuthInBody;
    }

    public T setClientAuthInBody(boolean clientAuthInBody) {
        this.clientAuthInBody = clientAuthInBody;
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

    @JsonInclude(JsonInclude.Include.NON_NULL)
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

    public String getUserPropagationParameter() {
        return userPropagationParameter;
    }

    public T setUserPropagationParameter(String userPropagationParameter) {
        this.userPropagationParameter = userPropagationParameter;
        return (T) this;
    }

    @JsonIgnore
    public Class getParameterizedClass() {
        ParameterizedType parameterizedType =
            (ParameterizedType)getClass().getGenericSuperclass();
        return (Class) parameterizedType.getActualTypeArguments()[0];
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;

        AbstractExternalOAuthIdentityProviderDefinition<?> that = (AbstractExternalOAuthIdentityProviderDefinition<?>) o;

        if (showLinkText != that.showLinkText) return false;
        if (skipSslValidation != that.skipSslValidation) return false;
        if (!Objects.equals(authUrl, that.authUrl)) return false;
        if (!Objects.equals(tokenUrl, that.tokenUrl)) return false;
        if (!Objects.equals(tokenKeyUrl, that.tokenKeyUrl)) return false;
        if (!Objects.equals(tokenKey, that.tokenKey)) return false;
        if (!Objects.equals(linkText, that.linkText)) return false;
        if (!Objects.equals(relyingPartyId, that.relyingPartyId))
            return false;
        if (!Objects.equals(relyingPartySecret, that.relyingPartySecret))
            return false;
        if (!Objects.equals(scopes, that.scopes)) return false;
        if (!Objects.equals(issuer, that.issuer)) return false;
        if (!Objects.equals(userPropagationParameter, that.userPropagationParameter)) return false;
        return Objects.equals(responseType, that.responseType);

    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (authUrl != null ? authUrl.hashCode() : 0);
        result = 31 * result + (tokenUrl != null ? tokenUrl.hashCode() : 0);
        result = 31 * result + (tokenKeyUrl != null ? tokenKeyUrl.hashCode() : 0);
        result = 31 * result + (tokenKey != null ? tokenKey.hashCode() : 0);
        result = 31 * result + (linkText != null ? linkText.hashCode() : 0);
        result = 31 * result + (showLinkText ? 1 : 0);
        result = 31 * result + (skipSslValidation ? 1 : 0);
        result = 31 * result + (relyingPartyId != null ? relyingPartyId.hashCode() : 0);
        result = 31 * result + (relyingPartySecret != null ? relyingPartySecret.hashCode() : 0);
        result = 31 * result + (scopes != null ? scopes.hashCode() : 0);
        result = 31 * result + (issuer != null ? issuer.hashCode() : 0);
        result = 31 * result + (userPropagationParameter != null ? userPropagationParameter.hashCode() : 0);
        result = 31 * result + (responseType != null ? responseType.hashCode() : 0);
        return result;
    }
}
