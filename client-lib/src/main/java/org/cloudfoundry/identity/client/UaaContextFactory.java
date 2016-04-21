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
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
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
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static org.cloudfoundry.identity.client.token.GrantType.AUTHORIZATION_CODE;
import static org.cloudfoundry.identity.client.token.GrantType.PASSWORD_WITH_PASSCODE;
import static org.springframework.security.oauth2.common.AuthenticationScheme.header;

public class UaaContextFactory {

    /**
     * UAA Base URI
     */
    private final URI uaaURI;

    /**
     * Instantiates a context factory to authenticate against the UAA
     * @param uaaURI the UAA base URI
     */
    private UaaContextFactory(URI uaaURI) {
        this.uaaURI = uaaURI;
    }

    private String tokenPath = "/oauth/token";
    private String authorizePath = "/oauth/authorize";

    /**
     * Instantiates a context factory to authenticate against the UAA
     * The default token path, /oauth/token, and authorize path, /oauth/authorize are set.
     * @param uaaURI the UAA base URI
     */
    public static UaaContextFactory factory(URI uaaURI) {
        return new UaaContextFactory(uaaURI);
    }

    /**
     * Sets the token endpoint path. If not invoked, the default is /oauth/token
     * @param path the path for the token endpoint.
     * @return this mutable object
     */
    public UaaContextFactory tokenPath(String path) {
        this.tokenPath = path;
        return this;
    }

    /**
     * Sets the authorize endpoint path. If not invoked, the default is /oauth/authorize
     * @param path the path for the authorize endpoint.
     * @return this mutable object
     */
    public UaaContextFactory authorizePath(String path) {
        this.authorizePath = path;
        return this;
    }

    /**
     * Creates a new {@link TokenRequest} object.
     * The object will have the token an authorize endpoints already configured.
     * @return the new token request that can be used for an access token request.
     */
    public TokenRequest tokenRequest() {
        UriComponentsBuilder tokenURI = UriComponentsBuilder.newInstance();
        tokenURI.uri(uaaURI);
        tokenURI.path(tokenPath);
        UriComponentsBuilder authorizationURI = UriComponentsBuilder.newInstance();
        authorizationURI.uri(uaaURI);
        authorizationURI.path(authorizePath);
        return new TokenRequest(tokenURI.build().toUri(), authorizationURI.build().toUri());
    }


    /**
     * Authenticates the client and optionally the user and retrieves an access token
     * Token request must be valid, see {@link TokenRequest#isValid()}
     * @param request - a fully configured token request
     * @return an authenticated UAA context with
     * @throws NullPointerException if the request object is null
     * @throws IllegalArgumentException if the token request is invalid
     */
    public UaaContext authenticate(TokenRequest request) {
        if (request == null) {
            throw new NullPointerException(TokenRequest.class.getName() + " cannot be null.");
        }
        if (!request.isValid()) {
            throw new IllegalArgumentException("Invalid token request.");
        }
        switch (request.getGrantType()) {
            case CLIENT_CREDENTIALS: return authenticateClientCredentials(request);
            case PASSWORD:
            case PASSWORD_WITH_PASSCODE: return authenticatePassword(request);
            case AUTHORIZATION_CODE: return authenticateAuthCode(request);
            case AUTHORIZATION_CODE_WITH_TOKEN: return authenticateAuthCodeWithToken(request);
            default: throw new UnsupportedGrantTypeException("Not implemented:"+request.getGrantType());
        }
    }

    /**
     * Not yet implemented
     * @param tokenRequest - a configured TokenRequest
     * @return an authenticated {@link UaaContext}
     */
    protected UaaContext authenticateAuthCode(final TokenRequest tokenRequest) {
        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setPreEstablishedRedirectUri(tokenRequest.getRedirectUriRedirectUri().toString());
        details.setUserAuthorizationUri(tokenRequest.getAuthorizationEndpoint().toString());
        configureResourceDetails(tokenRequest, details);
        setClientCredentials(tokenRequest, details);
        setRequestScopes(tokenRequest, details);

        //begin - work around for not having UI for now
        DefaultOAuth2ClientContext oAuth2ClientContext = new DefaultOAuth2ClientContext();
        oAuth2ClientContext.getAccessTokenRequest().setStateKey(tokenRequest.getState());
        oAuth2ClientContext.setPreservedState(tokenRequest.getState(), details.getPreEstablishedRedirectUri());
        oAuth2ClientContext.getAccessTokenRequest().setCurrentUri(details.getPreEstablishedRedirectUri());
        //end - work around for not having UI for now

        OAuth2RestTemplate template = new OAuth2RestTemplate(details, oAuth2ClientContext);
        template.getAccessToken();
        throw new UnsupportedOperationException(AUTHORIZATION_CODE +" is not yet implemented");
    }

    /**
     * Performs and authorization_code grant, but uses a token to assert the user's identity.
     * @param tokenRequest - a configured TokenRequest
     * @return an authenticated {@link UaaContext}
     */
    protected UaaContext authenticateAuthCodeWithToken(final TokenRequest tokenRequest) {
        AuthorizationCodeAccessTokenProvider provider = new AuthorizationCodeAccessTokenProvider() {
            @Override
            protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
                getRestTemplate(); // force initialization
                MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
                return new HttpMessageConverterExtractor<OAuth2AccessToken>(CompositeAccessToken.class, Arrays.asList(converter));
            }
        };
        enhanceRequestParameters(tokenRequest, provider);
        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setPreEstablishedRedirectUri(tokenRequest.getRedirectUriRedirectUri().toString());
        configureResourceDetails(tokenRequest, details);
        setClientCredentials(tokenRequest, details);
        setRequestScopes(tokenRequest, details);
        details.setUserAuthorizationUri(tokenRequest.getAuthorizationEndpoint().toString());
        DefaultOAuth2ClientContext oAuth2ClientContext = new DefaultOAuth2ClientContext();
        oAuth2ClientContext.getAccessTokenRequest().setStateKey(tokenRequest.getState());
        oAuth2ClientContext.setPreservedState(tokenRequest.getState(), details.getPreEstablishedRedirectUri());
        oAuth2ClientContext.getAccessTokenRequest().setCurrentUri(details.getPreEstablishedRedirectUri());
        Map<String, List<String>> headers = (Map<String, List<String>>) oAuth2ClientContext.getAccessTokenRequest().getHeaders();
        headers.put("Authorization", Arrays.asList("bearer " + tokenRequest.getAuthCodeAPIToken()));
        OAuth2RestTemplate template = new OAuth2RestTemplate(details, oAuth2ClientContext);
        template.setAccessTokenProvider(provider);
        OAuth2AccessToken token = template.getAccessToken();
        return new UaaContextImpl(tokenRequest, template, (CompositeAccessToken) token);
    }


    /**
     * Performs a {@link org.cloudfoundry.identity.client.token.GrantType#PASSWORD authentication}
     * @param tokenRequest - a configured TokenRequest
     * @return an authenticated {@link UaaContext}
     */
    protected UaaContext authenticatePassword(final TokenRequest tokenRequest) {
        ResourceOwnerPasswordAccessTokenProvider provider = new ResourceOwnerPasswordAccessTokenProvider() {
            @Override
            protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
                getRestTemplate(); // force initialization
                MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
                return new HttpMessageConverterExtractor<OAuth2AccessToken>(CompositeAccessToken.class, Arrays.asList(converter));
            }
        };
        enhanceRequestParameters(tokenRequest, provider);
        ResourceOwnerPasswordResourceDetails details = new ResourceOwnerPasswordResourceDetails();
        configureResourceDetails(tokenRequest, details);
        setUserCredentials(tokenRequest, details);
        setClientCredentials(tokenRequest, details);
        setRequestScopes(tokenRequest, details);
        OAuth2RestTemplate template = new OAuth2RestTemplate(details,new DefaultOAuth2ClientContext());
        template.setAccessTokenProvider(provider);
        OAuth2AccessToken token = template.getAccessToken();
        return new UaaContextImpl(tokenRequest, template, (CompositeAccessToken) token);
    }

    /**
     * Adds a request enhancer to the provider.
     * Currently only two request parameters are being enhanced
     * 1. If the {@link TokenRequest} wants an id_token the <code>id_token token</code> values are added as a response_type parameter
     * 2. If the {@link TokenRequest} is a {@link org.cloudfoundry.identity.client.token.GrantType#PASSWORD_WITH_PASSCODE}
     * the <code>passcode</code> parameter will be added to the request
     * @param tokenRequest the token request, expected to be a password grant
     * @param provider the provider to enhance
     */
    protected void enhanceRequestParameters(TokenRequest tokenRequest, OAuth2AccessTokenSupport provider) {
        provider.setTokenRequestEnhancer( //add id_token to the response type if requested.
            (AccessTokenRequest request,
             OAuth2ProtectedResourceDetails resource,
             MultiValueMap<String, String> form,
             HttpHeaders headers) -> {
                if (tokenRequest.wantsIdToken()) {
                    form.put(OAuth2Utils.RESPONSE_TYPE, Arrays.asList("id_token token"));
                }
                if (tokenRequest.getGrantType()==PASSWORD_WITH_PASSCODE) {
                    form.put("passcode", Arrays.asList(tokenRequest.getPasscode()));
                }
            }
        );
    }

    /**
     * Performs a {@link org.cloudfoundry.identity.client.token.GrantType#CLIENT_CREDENTIALS authentication}
     * @param request - a configured TokenRequest
     * @return an authenticated {@link UaaContext}
     */

    protected UaaContext authenticateClientCredentials(TokenRequest request) {
        ClientCredentialsResourceDetails details = new ClientCredentialsResourceDetails();
        configureResourceDetails(request, details);
        setClientCredentials(request, details);
        setRequestScopes(request, details);
        OAuth2RestTemplate template = new OAuth2RestTemplate(details,new DefaultOAuth2ClientContext());
        OAuth2AccessToken token = template.getAccessToken();
        CompositeAccessToken result = new CompositeAccessToken(token);
        return new UaaContextImpl(request, template, result);
    }

    /**
     * Sets the token endpoint on the resource details
     * Sets the authentication scheme to be {@link org.springframework.security.oauth2.common.AuthenticationScheme#header}
     * @param tokenRequest the token request containing the token endpoint
     * @param details the details object that will be configured
     */
    protected void configureResourceDetails(TokenRequest tokenRequest, BaseOAuth2ProtectedResourceDetails details) {
        details.setAuthenticationScheme(header);
        details.setAccessTokenUri(tokenRequest.getTokenEndpoint().toString());
    }

    /**
     * Sets the requested scopes on the resource details, if and only if the requested scopes are not null
     * @param tokenRequest the token request containing the requested scopes, if any
     * @param details the details object that will be configured
     */
    protected void setRequestScopes(TokenRequest tokenRequest, BaseOAuth2ProtectedResourceDetails details) {
        if (!Objects.isNull(tokenRequest.getScopes())) {
            details.setScope(new LinkedList(tokenRequest.getScopes()));
        }
    }

    /**
     * Sets the client_id and client_secret on the resource details object
     * @param tokenRequest the token request containing the client_id and client_secret
     * @param details the details object that. will be configured
     */
    protected void setClientCredentials(TokenRequest tokenRequest, BaseOAuth2ProtectedResourceDetails details) {
        details.setClientId(tokenRequest.getClientId());
        details.setClientSecret(tokenRequest.getClientSecret());
    }

    /**
     * Sets the username and password on the resource details object
     * @param tokenRequest the token request containing the client_id and client_secret
     * @param details the details object that. will be configured
     */
    protected void setUserCredentials(TokenRequest tokenRequest, ResourceOwnerPasswordResourceDetails details) {
        details.setUsername(tokenRequest.getUsername());
        details.setPassword(tokenRequest.getPassword());
    }

}
