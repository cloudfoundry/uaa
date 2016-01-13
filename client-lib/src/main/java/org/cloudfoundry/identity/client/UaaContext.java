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

package org.cloudfoundry.identity.client;

import org.cloudfoundry.identity.client.token.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.springframework.web.client.RestTemplate;

public interface UaaContext {

    /**
     * Returns true if the context is authenticated and has an access token
     * @return true if the context is authenticated and has an access token
     */
    boolean hasAccessToken();

    /**
     * Returns true if the context contains an OpenID Connect id_token.
     * The token can be retrieved by {@link CompositeAccessToken#getIdTokenValue()}
     * @return true if the context contains an OpenID Connect id_token
     */
    boolean hasIdToken();

    /**
     * Returns true if the context has a refresh token
     * The token can be retrieved by {@link CompositeAccessToken#getRefreshToken()}
     * @return true if the context has a refresh token
     */
    boolean hasRefreshToken();

    /**
     * Returns the token for this context. A token object will always contain an access token and may
     * contain an OpenID Connect id_token and/or a refresh token
     * @return the token for this context
     */
    CompositeAccessToken getToken();

    /**
     * Returns the token request that was used to acquire the token
     * @return the token request that was used to acquire the token
     */
    TokenRequest getTokenRequest();

    /**
     * Returns a {@link org.springframework.security.oauth2.client.OAuth2RestTemplate}
     * that has the access token enabled on this object.
     * @return the rest template that can be used to invoke UAA APIs
     */
    RestTemplate getRestTemplate();


}
