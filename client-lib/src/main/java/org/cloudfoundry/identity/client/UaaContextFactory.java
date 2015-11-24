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
import org.springframework.http.HttpHeaders;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.RequestEnhancer;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpMessageConverterExtractor;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Objects;

import static org.springframework.security.oauth2.common.AuthenticationScheme.header;

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
        if (!request.isValid()) {
            throw new IllegalArgumentException("Invalid token request.");
        }
        switch (request.getGrantType()) {
            case CLIENT_CREDENTIALS: return authenticateClientCredentials(request);
            case PASSWORD: return authenticatePassword(request);
            default: throw new UnsupportedGrantTypeException("Not implemented:"+request.getGrantType());
        }
    }

    protected UaaContext authenticatePassword(final TokenRequest tokenRequest) {
        ResourceOwnerPasswordAccessTokenProvider provider = new ResourceOwnerPasswordAccessTokenProvider() {
            @Override
            protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
                getRestTemplate(); // force initialization
                MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
                return new HttpMessageConverterExtractor<OAuth2AccessToken>(CompositeAccessToken.class, Arrays.asList(converter));
            }
        };
        provider.setTokenRequestEnhancer( //add id_token to the response type if requested.
            (AccessTokenRequest request,
             OAuth2ProtectedResourceDetails resource,
             MultiValueMap<String, String> form,
             HttpHeaders headers) -> {
                if (tokenRequest.wantsIdToken()) {
                    form.put(OAuth2Utils.RESPONSE_TYPE, Arrays.asList("id_token token"));
                }

            }
        );
        ResourceOwnerPasswordResourceDetails details = new ResourceOwnerPasswordResourceDetails();
        details.setUsername(tokenRequest.getUsername());
        details.setPassword(tokenRequest.getPassword());
        details.setClientId(tokenRequest.getClientId());
        details.setClientSecret(tokenRequest.getClientSecret());
        if (!Objects.isNull(tokenRequest.getScopes())) {
            details.setScope(new LinkedList(tokenRequest.getScopes()));
        }
        details.setClientAuthenticationScheme(header);
        details.setAccessTokenUri(tokenRequest.getTokenEndpoint().toString());
        OAuth2RestTemplate template = new OAuth2RestTemplate(details,new DefaultOAuth2ClientContext());
        template.setAccessTokenProvider(provider);
        OAuth2AccessToken token = template.getAccessToken();
        return new UaaContextImpl(tokenRequest, template, (CompositeAccessToken) token);
    }

    protected UaaContext authenticateClientCredentials(TokenRequest request) {
        if (!request.isValid()) {

        }
        ClientCredentialsResourceDetails details = new ClientCredentialsResourceDetails();
        details.setClientId(request.getClientId());
        details.setClientSecret(request.getClientSecret());
        details.setAccessTokenUri(request.getTokenEndpoint().toString());
        details.setClientAuthenticationScheme(header);
        OAuth2RestTemplate template = new OAuth2RestTemplate(details,new DefaultOAuth2ClientContext());
        OAuth2AccessToken token = template.getAccessToken();
        CompositeAccessToken result = new CompositeAccessToken(token);
        return new UaaContextImpl(request, template, result);
    }

    public static class PasswordTokenRequestEnhancer implements RequestEnhancer {
        private final TokenRequest request;

        public PasswordTokenRequestEnhancer(TokenRequest request) {
            this.request = request;
        }

        @Override
        public void enhance(AccessTokenRequest request, OAuth2ProtectedResourceDetails resource, MultiValueMap<String, String> form, HttpHeaders headers) {

        }


    }

}
