/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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
package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonProperty;

public class OpenIdConfiguration {

    @JsonProperty("issuer")
    private String issuer;
    @JsonProperty("authorization_endpoint")
    private String authUrl;
    @JsonProperty("token_endpoint")
    private String tokenUrl;
    @JsonProperty("token_endpoint_auth_methods_supported")
    private String[] tokenAMR = new String[]{"client_secret_basic", "client_secret_post"};
    @JsonProperty("token_endpoint_auth_signing_alg_values_supported")
    private String[] tokenEndpointAuthSigningValues = new String[]{"RS256", "HS256"};
    @JsonProperty("userinfo_endpoint")
    private String userInfoUrl;
    @JsonProperty("jwks_uri")
    private String jwksUri;
    @JsonProperty("scopes_supported")
    private String[] scopes = new String[]{"openid", "profile", "email", "phone", "roles", "user_attributes"};
    @JsonProperty("response_types_supported")
    private String[] responseTypes = new String[]{"code", "code id_token", "id_token", "token id_token"};
    @JsonProperty("subject_types_supported")
    private String[] subjectTypesSupported = new String[]{"public"};
    @JsonProperty("id_token_signing_alg_values_supported")
    private String[] idTokenSigningAlgValues = new String[]{"RS256", "HS256"};
    @JsonProperty("id_token_encryption_alg_values_supported")
    private String[] requestObjectSigningAlgValues = new String[]{"none"};
    @JsonProperty("claim_types_supported")
    private String[] claimTypesSupported = new String[]{"normal"};
    @JsonProperty("claims_supported")
    private String[] claimsSupported = new String[]{"sub", "user_name", "origin", "iss", "auth_time", "amr", "acr", "client_id",
        "aud", "zid", "grant_type", "user_id", "azp", "scope", "exp", "iat", "jti", "rev_sig", "cid", "given_name", "family_name", "phone_number", "email"};
    @JsonProperty("claims_parameter_supported")
    private boolean claimsParameterSupported = false;
    @JsonProperty("service_documentation")
    private String serviceDocumentation = "http://docs.cloudfoundry.org/api/uaa/";
    @JsonProperty("ui_locales_supported")
    private String[] uiLocalesSupported = new String[]{"en-US"};

    //For json serialization
    public OpenIdConfiguration() {}

    public OpenIdConfiguration(String contextPath, String issuer) {
        this.issuer = issuer;
        this.authUrl = contextPath + "/oauth/authorize";
        this.tokenUrl = contextPath + "/oauth/token";
        this.userInfoUrl = contextPath + "/userinfo";
        this.jwksUri = contextPath + "/token_keys";
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAuthUrl() {
        return authUrl;
    }

    public void setAuthUrl(String authUrl) {
        this.authUrl = authUrl;
    }

    public String getTokenUrl() {
        return tokenUrl;
    }

    public void setTokenUrl(String tokenUrl) {
        this.tokenUrl = tokenUrl;
    }

    public String[] getTokenAMR() {
        return tokenAMR;
    }

    public void setTokenAMR(String[] tokenAMR) {
        this.tokenAMR = tokenAMR;
    }

    public String[] getTokenEndpointAuthSigningValues() {
        return tokenEndpointAuthSigningValues;
    }

    public void setTokenEndpointAuthSigningValues(String[] tokenEndpointAuthSigningValues) {
        this.tokenEndpointAuthSigningValues = tokenEndpointAuthSigningValues;
    }

    public String getUserInfoUrl() {
        return userInfoUrl;
    }

    public void setUserInfoUrl(String userInfoUrl) {
        this.userInfoUrl = userInfoUrl;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public String[] getScopes() {
        return scopes;
    }

    public void setScopes(String[] scopes) {
        this.scopes = scopes;
    }

    public String[] getResponseTypes() {
        return responseTypes;
    }

    public void setResponseTypes(String[] responseTypes) {
        this.responseTypes = responseTypes;
    }

    public String[] getSubjectTypesSupported() {
        return subjectTypesSupported;
    }

    public void setSubjectTypesSupported(String[] subjectTypesSupported) {
        this.subjectTypesSupported = subjectTypesSupported;
    }

    public String[] getIdTokenSigningAlgValues() {
        return idTokenSigningAlgValues;
    }

    public void setIdTokenSigningAlgValues(String[] idTokenSigningAlgValues) {
        this.idTokenSigningAlgValues = idTokenSigningAlgValues;
    }

    public String[] getRequestObjectSigningAlgValues() {
        return requestObjectSigningAlgValues;
    }

    public void setRequestObjectSigningAlgValues(String[] requestObjectSigningAlgValues) {
        this.requestObjectSigningAlgValues = requestObjectSigningAlgValues;
    }

    public String[] getClaimTypesSupported() {
        return claimTypesSupported;
    }

    public void setClaimTypesSupported(String[] claimTypesSupported) {
        this.claimTypesSupported = claimTypesSupported;
    }

    public String[] getClaimsSupported() {
        return claimsSupported;
    }

    public void setClaimsSupported(String[] claimsSupported) {
        this.claimsSupported = claimsSupported;
    }

    public boolean isClaimsParameterSupported() {
        return claimsParameterSupported;
    }

    public void setClaimsParameterSupported(boolean claimsParameterSupported) {
        this.claimsParameterSupported = claimsParameterSupported;
    }

    public String getServiceDocumentation() {
        return serviceDocumentation;
    }

    public void setServiceDocumentation(String serviceDocumentation) {
        this.serviceDocumentation = serviceDocumentation;
    }

    public String[] getUiLocalesSupported() {
        return uiLocalesSupported;
    }

    public void setUiLocalesSupported(String[] uiLocalesSupported) {
        this.uiLocalesSupported = uiLocalesSupported;
    }
}
