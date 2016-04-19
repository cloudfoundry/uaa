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
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

public class UaaContextImpl implements UaaContext {
    private CompositeAccessToken token;
    private TokenRequest request;
    private OAuth2RestTemplate template;

    public UaaContextImpl(TokenRequest request, OAuth2RestTemplate template, CompositeAccessToken token) {
        this.request = request;
        this.template = template;
        this.token = token;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasAccessToken() {
        return token!=null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasIdToken() {
        return token!=null && StringUtils.hasText(token.getIdTokenValue());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean hasRefreshToken() {
        return token!=null && token.getRefreshToken()!=null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public TokenRequest getTokenRequest() {
        return request;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public RestTemplate getRestTemplate() {
        return template;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CompositeAccessToken getToken() {
        return token;
    }
}
