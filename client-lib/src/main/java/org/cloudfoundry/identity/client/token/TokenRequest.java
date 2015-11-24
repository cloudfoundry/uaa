/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.client.token;

import java.net.URI;

public class TokenRequest {

    private GrantType grantType;
    private String clientId;
    private String clientSecret;
    private String username;
    private String password;
    private URI tokenEndpoint;
    private URI authorizationEndpoint;

    public TokenRequest(URI tokenEndpoint, URI authorizationEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public boolean isValid() {
        return false;
    }

    public URI getTokenEndpoint() {
        return tokenEndpoint;
    }

    public TokenRequest setTokenEndpoint(URI tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
        return this;
    }

    public String getClientId() {
        return clientId;
    }

    public TokenRequest setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public TokenRequest setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    public GrantType getGrantType() {
        return grantType;
    }

    public TokenRequest setGrantType(GrantType grantType) {
        this.grantType = grantType;
        return this;
    }

    public String getPassword() {
        return password;
    }

    public TokenRequest setPassword(String password) {
        this.password = password;
        return this;
    }

    public String getUsername() {
        return username;
    }

    public TokenRequest setUsername(String username) {
        this.username = username;
        return this;
    }

    public URI getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public TokenRequest setAuthorizationEndpoint(URI authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
        return this;
    }
}
