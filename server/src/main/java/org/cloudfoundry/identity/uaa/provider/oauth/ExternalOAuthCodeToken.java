/*
 * *****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class ExternalOAuthCodeToken implements Authentication {
    private String code;
    private String origin;
    private String redirectUrl;
    private String idToken;
    private String accessToken;
    private String signedRequest;
    private String requestContextPath;
    private UaaAuthenticationDetails details;

    public ExternalOAuthCodeToken(String code, String origin, String redirectUrl) {
        this.code = code;
        this.origin = origin;
        this.redirectUrl = redirectUrl;
    }

    public ExternalOAuthCodeToken(String code, String origin, String redirectUrl, String idToken, String accessToken, String signedRequest) {
        this(code, origin, redirectUrl);
        this.idToken = idToken;
        this.accessToken = accessToken;
        this.signedRequest = signedRequest;
    }

    public ExternalOAuthCodeToken(String code, String origin, String redirectUrl, String idToken, String accessToken, String signedRequest, UaaAuthenticationDetails details) {
        this(code, origin, redirectUrl, idToken, accessToken, signedRequest);
        this.details = details;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public void setDetails(UaaAuthenticationDetails details) {
        this.details = details;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return UaaAuthority.USER_AUTHORITIES;
    }

    @Override
    public Object getCredentials() {
        return getCode();
    }

    @Override
    public Object getDetails() {
        return details;
    }

    public UaaAuthenticationDetails getUaaAuthenticationDetails() {
        return details;
    }

    @Override
    public Object getPrincipal() {
        return getCode();
    }

    @Override
    public boolean isAuthenticated() {
        return false;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
    }

    @Override
    public String getName() {
        return getCode();
    }

    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getSignedRequest() {
        return signedRequest;
    }

    public void setSignedRequest(String signedRequest) {
        this.signedRequest = signedRequest;
    }

    public String getRequestContextPath() {
        return requestContextPath;
    }

    public void setRequestContextPath(String requestContextPath) {
        this.requestContextPath = requestContextPath;
    }
}
