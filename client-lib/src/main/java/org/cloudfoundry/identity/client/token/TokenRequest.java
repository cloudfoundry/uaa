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
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * A token request contains all the information needed to retrieve a token from the UAA.
 * the {@link #isValid()} method validates the token request object
 * for each {@link GrantType}
 *
 */
public class TokenRequest {

    private GrantType grantType;
    private String clientId;
    private String clientSecret;
    private String username;
    private String password;
    private String passcode;
    private Set<String> scopes;
    private URI tokenEndpoint;
    private URI authorizationEndpoint;
    private boolean idToken = false;
    private URI redirectUri;
    private String authCodeAPIToken;
    private String state;
    private boolean skipSslValidation = false;
    private String authorizationCode;

    /**
     * Constructs a token request
     * @param tokenEndpoint - required for all grant types
     * @param authorizationEndpoint - maybe required only for {@link GrantType#AUTHORIZATION_CODE} and {@link GrantType#IMPLICIT}
     */
    public TokenRequest(URI tokenEndpoint, URI authorizationEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
        this.authorizationEndpoint = authorizationEndpoint;
    }

    /**
     * Returns true if this object contains enough information to retrieve a token
     * @return true if this object contains enough information to retrieve a token
     */
    public boolean isValid() {
        if (grantType==null) {
            return false;
        }
        switch (grantType) {
            case CLIENT_CREDENTIALS:
                return !hasAnyNullValues(
                    Arrays.asList(
                        tokenEndpoint,
                        clientId,
                        clientSecret
                    )
                );
            case PASSWORD:
                return !hasAnyNullValues(
                    Arrays.asList(
                        tokenEndpoint,
                        clientId,
                        clientSecret,
                        username,
                        password
                    )
                );
            case PASSWORD_WITH_PASSCODE:
                return !hasAnyNullValues(
                    Arrays.asList(
                        tokenEndpoint,
                        clientId,
                        clientSecret,
                        username,
                        passcode
                    )
                );
            case AUTHORIZATION_CODE:
                return !hasAnyNullValues(
                    Arrays.asList(
                        tokenEndpoint,
                        authorizationEndpoint,
                        clientId,
                        clientSecret,
                        username,
                        password,
                        redirectUri,
                        state
                    )
                );
            case AUTHORIZATION_CODE_WITH_TOKEN:
                return !hasAnyNullValues(
                    Arrays.asList(
                        tokenEndpoint,
                        authorizationEndpoint,
                        clientId,
                        clientSecret,
                        redirectUri,
                        authCodeAPIToken,
                        state
                    )
                );
            case FETCH_TOKEN_FROM_CODE:
                return !hasAnyNullValues(
                    Arrays.asList(
                        tokenEndpoint,
                        clientId,
                        clientSecret,
                        redirectUri,
                        authorizationCode
                    )
                );
            default: return false;
        }
    }

    /**
     * @return the token endpoint URI, for example http://localhost:8080/uaa/oauth/token
     */
    public URI getTokenEndpoint() {
        return tokenEndpoint;
    }

    /**
     * Sets the token endpoint. Must be the endpoint of the UAA server, for example http://localhost:8080/uaa/oauth/token
     * @param tokenEndpoint a valid URI pointing to the UAA token endpoint
     * @return this mutable object
     */
    public TokenRequest setTokenEndpoint(URI tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
        return this;
    }

    /**
     * Returns the client ID, if set, that will be used to authenticate the client
     * @return the client ID if set
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Sets the client ID to be used for authentication during the token request
     * @param clientId a string, no more than 255 characters identifying a valid client on the UAA
     * @return this mutable object
     */
    public TokenRequest setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    /**
     * Returns the client secret, if set, that will be used to authenticate the client
     * @return the client secret if set
     */
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * Sets the client secret to be used for authentication during the token request
     * @param clientSecret a string representing the password for a valid client on the UAA
     * @return this mutable object
     */
    public TokenRequest setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
        return this;
    }

    /**
     * Returns the grant type for this token request. Null if none has been set.
     * @return the grant type for this token request. Null if none has been set.
     */
    public GrantType getGrantType() {
        return grantType;
    }

    /**
     * Sets the grant type
     * @param grantType a grant type
     * @return this mutable object
     */
    public TokenRequest setGrantType(GrantType grantType) {
        this.grantType = grantType;
        return this;
    }

    /**
     * Returns the user password used during {@link GrantType#PASSWORD} token requests
     * @return the user password used during {@link GrantType#PASSWORD} token requests
     */
    public String getPassword() {
        return password;
    }

    /**
     * Sets the user password used during {@link GrantType#PASSWORD} token requests
     * @param password a clear text password
     * @return this mutable object
     */
    public TokenRequest setPassword(String password) {
        this.password = password;
        return this;
    }

    /**
     * Returns the username to be used during {@link GrantType#PASSWORD} token requests
     * @return the username to be used during {@link GrantType#PASSWORD} token requests
     */
    public String getUsername() {
        return username;
    }

    /**
     * Sets the username to be used during {@link GrantType#PASSWORD} token requests
     * @param username the username to be used during {@link GrantType#PASSWORD} token requests
     * @return this mutable object
     */
    public TokenRequest setUsername(String username) {
        this.username = username;
        return this;
    }

    /**
     * @return the authorize endpoint URI, for example http://localhost:8080/uaa/oauth/authorize
     */
    public URI getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    /**
     * Sets the authorize endpoint URI, for example http://localhost:8080/uaa/oauth/authorize
     * @param authorizationEndpoint the authorize endpoint URI, for example http://localhost:8080/uaa/oauth/authorize
     * @return this mutable object
     */
    public TokenRequest setAuthorizationEndpoint(URI authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
        return this;
    }

    /**
     * When invoked, this token request should return an id_token in addition to the access token
     * @return this mutable object
     */
    public TokenRequest withIdToken() {
        idToken = true;
        return this;
    }

    /**
     * Returns true if an id_token has been reqeusted, {@link #withIdToken()} has been invoked.
     * @return true if an id_token has been reqeusted
     */
    public boolean wantsIdToken() {
        return idToken;
    }

    /**
     * Sets the requested/narrowed scope list for this token request.
     * Use this if you would like to limit the scopes in the access token
     * Setting this to null indicates that you would like the access token to contain all available scopes
     * @param scopes a set of strings representing requested scopes, or null to request all scopes
     * @return this mutable object
     */
    public TokenRequest setScopes(Collection<String> scopes) {
        this.scopes = scopes==null ? null : new HashSet<>(scopes);
        return this;
    }

    /**
     * Returns the list of requested scopes, or null if no scopes have been requested.
     * @return the list of requested scopes, or null if no scopes have been requested.
     */
    public Set<String> getScopes() {
        return scopes;
    }

    /**
     * Returns the redirect_uri for an {@link GrantType#AUTHORIZATION_CODE} or {@link GrantType#IMPLICIT} token request
     * @return the redirect_uri for an {@link GrantType#AUTHORIZATION_CODE} or {@link GrantType#IMPLICIT} token request
     */
    public URI getRedirectUri() {
        return redirectUri;
    }

    /**
     * Sets the redirect_uri for an {@link GrantType#AUTHORIZATION_CODE} or {@link GrantType#IMPLICIT} token request
     * @param redirectUri the redirect_uri for an {@link GrantType#AUTHORIZATION_CODE} or {@link GrantType#IMPLICIT} token request
     * @return this mutable object
     */
    public TokenRequest setRedirectUri(URI redirectUri) {
        this.redirectUri = redirectUri;
        return this;
    }

    /**
     * Returns the UAA token that will be used if this token request is an
     * {@link GrantType#AUTHORIZATION_CODE_WITH_TOKEN} grant.
     * @return the token set or null if not set
     */
    public String getAuthCodeAPIToken() {
        return authCodeAPIToken;
    }

    /**
     * Sets the token used as authentication mechanism when using
     * the {@link GrantType#AUTHORIZATION_CODE_WITH_TOKEN} grant.
     * @param authCodeAPIToken - a valid UAA token
     * @return this mutable object
     */
    public TokenRequest setAuthCodeAPIToken(String authCodeAPIToken) {
        this.authCodeAPIToken = authCodeAPIToken;
        return this;
    }

    /**
     * Returns the passcode if set with {@link #setPasscode(String)}, null otherwise.
     * Passcode is used with using the {@link GrantType#PASSWORD_WITH_PASSCODE} grant type.
     * @return the passcode if set, null otherwise.
     */
    public String getPasscode() {
        return passcode;
    }

    /**
     * Sets the passcode to be used with the {@link GrantType#PASSWORD_WITH_PASSCODE} grant type.
     * @param passcode a valid passcode retrieved from a logged in session at
     * http://uaa.domain/passcode
     * @return this mutable object
     */
    public TokenRequest setPasscode(String passcode) {
        this.passcode = passcode;
        return this;
    }

    /**
     * Returns the state key, used with
     * {@link GrantType#AUTHORIZATION_CODE} and
     * {@link GrantType#IMPLICIT} and
     * {@link GrantType#AUTHORIZATION_CODE_WITH_TOKEN}
     * @return String representing a random string
     */
    public String getState() {
        return state;
    }

    /**
     * Sets the state key, used with
     * {@link GrantType#AUTHORIZATION_CODE} and
     * {@link GrantType#IMPLICIT} and
     * {@link GrantType#AUTHORIZATION_CODE_WITH_TOKEN}
     * @param state - a random string
     * @return this mutable object
     */
    public TokenRequest setState(String state) {
        this.state = state;
        return this;
    }

    /**
     * Set to true if you wish to skip all SSL validation
     * Useful for self signed certificates.
     * @param skipSslValidation
     * @return this mutable object
     */
    public TokenRequest setSkipSslValidation(boolean skipSslValidation) {
        this.skipSslValidation = skipSslValidation;
        return this;
    }

    /**
     * Returns true if the system will skip all SSL validation
     * False is default
     * @return true if the request has been configured to skip SSL validation
     */
    public boolean isSkipSslValidation() {
        return skipSslValidation;
    }

    /**
     * Sets the authorization code for a {@link GrantType#FETCH_TOKEN_FROM_CODE} grant.
     * @return the authorization code that was set.
     */
    public String getAuthorizationCode() {
        return authorizationCode;
    }

    /**
     * Sets the  authorization code for a {@link GrantType#FETCH_TOKEN_FROM_CODE} grant.
     * @param authorizationCode
     * @return this mutable object
     */
    public TokenRequest setAuthorizationCode(String authorizationCode) {
        this.authorizationCode = authorizationCode;
        return this;
    }

    /**
     * Returns true if the list or any item in the list is null
     * @param objects a list of items to be evaluated for null references
     * @return true if the list or any item in the list is null
     */
    protected boolean hasAnyNullValues(List<Object> objects) {
        if (Objects.isNull(objects)) {
            return true;
        }
        return objects.stream().filter(o -> Objects.isNull(o)).count() > 0;
    }
}
