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
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

public class UaaContextFactory {

    private final URI uaaUri;

    private UaaContextFactory(URI uaaUri) {
        this.uaaUri = uaaUri;
    }

    private String tokenPath = "/oauth/token";
    private String authorizePath = "/oauth/authorize";

    public static UaaContextFactory factory(URI uaaURI) {
        return new UaaContextFactory(uaaURI);
    }

    public UaaContextFactory tokenPath(String path) {
        this.tokenPath = path;
        return this;
    }

    public UaaContextFactory authorizePath(String path) {
        this.authorizePath = path;
        return this;
    }

    public TokenRequest tokenRequest() {
        UriComponentsBuilder tokenURI = UriComponentsBuilder.newInstance();
        tokenURI.uri(uaaUri);
        tokenURI.path(tokenPath);

        UriComponentsBuilder authorizationURI = UriComponentsBuilder.newInstance();
        authorizationURI.uri(uaaUri);
        authorizationURI.path(authorizePath);

        return new TokenRequest(tokenURI.build().toUri(), authorizationURI.build().toUri());
    }



    public UaaContext authenticate(TokenRequest request) {
        if (request == null) {
            throw new NullPointerException(TokenRequest.class.getName() + " cannot be null.");
        }
        switch (request.getGrantType()) {
            case CLIENT_CREDENTIALS: return authenticateClientCredentials(request);
            default: throw new UnsupportedGrantTypeException("Not implemented:"+request.getGrantType());
        }
    }

    protected UaaContext authenticateClientCredentials(TokenRequest request) {
        ClientCredentialsResourceDetails details = new ClientCredentialsResourceDetails();
        details.setClientId(request.getClientId());
        details.setClientSecret(request.getClientSecret());
        details.setAccessTokenUri(request.getTokenEndpoint().toString());
        details.setClientAuthenticationScheme(AuthenticationScheme.header);
        OAuth2RestTemplate template = new OAuth2RestTemplate(details,new DefaultOAuth2ClientContext());
        OAuth2AccessToken token = template.getAccessToken();
        CompositeAccessToken result = new CompositeAccessToken(token);
        return new UaaContextImpl(request, template, result);
    }

}
