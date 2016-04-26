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


import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.ProtocolException;
import org.apache.http.client.RedirectStrategy;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultRedirectStrategy;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpContext;
import org.cloudfoundry.identity.client.token.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.token.CompositeAccessToken;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProvider;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.OAuth2AccessTokenSupport;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.client.token.grant.implicit.ImplicitAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.UnsupportedGrantTypeException;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpMessageConverterExtractor;
import org.springframework.web.client.ResponseExtractor;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.net.ssl.SSLContext;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import static java.lang.String.format;
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
     * Returns the authorize URI
     * @return the UAA authorization URI
     */
    public URI getAuthorizeUri() {
        UriComponentsBuilder authorizationURI = UriComponentsBuilder.newInstance();
        authorizationURI.uri(uaaURI);
        authorizationURI.path(authorizePath);
        return authorizationURI.build().toUri();
    }

    /**
     * Returns the URI
     * @return
     */
    public URI getTokenUri() {
        UriComponentsBuilder tokenURI = UriComponentsBuilder.newInstance();
        tokenURI.uri(uaaURI);
        tokenURI.path(tokenPath);
        return tokenURI.build().toUri();
    }

    /**
     * Creates a new {@link TokenRequest} object.
     * The object will have the token an authorize endpoints already configured.
     * @return the new token request that can be used for an access token request.
     */
    public TokenRequest tokenRequest() {
        return new TokenRequest(getTokenUri(), getAuthorizeUri());
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
            case FETCH_TOKEN_FROM_CODE: return fetchTokenFromCode(request);
            default: throw new UnsupportedGrantTypeException("Not implemented:"+request.getGrantType());
        }
    }

    protected UaaContext fetchTokenFromCode(final TokenRequest request) {
        String clientBasicAuth = null;
        try {
            byte[] autbytes = Base64.encode(format("%s:%s", request.getClientId(),request.getClientSecret()).getBytes("UTF-8"));
            String base64 = new String(autbytes);
            clientBasicAuth = format("Basic %s", base64);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalArgumentException(e);
        }

        RestTemplate template = new RestTemplate();
        if (request.isSkipSslValidation()) {
            template.setRequestFactory(getNoValidatingClientHttpRequestFactory());
        }
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, clientBasicAuth);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String,String> form = new LinkedMultiValueMap<>();
        form.add(OAuth2Utils.GRANT_TYPE, "authorization_code");
        form.add(OAuth2Utils.REDIRECT_URI, request.getRedirectUri().toString());
        String responseType = "token";
        if (request.wantsIdToken()) {
            responseType += " id_token";
        }
        form.add(OAuth2Utils.RESPONSE_TYPE, responseType);
        form.add("code", request.getAuthorizationCode());

        ResponseEntity<CompositeAccessToken> token = template.exchange(request.getTokenEndpoint(), HttpMethod.POST, new HttpEntity<>(form, headers), CompositeAccessToken.class);
        return new UaaContextImpl(request, null, token.getBody());
    }

    /**
     * Not yet implemented
     * @param tokenRequest - a configured TokenRequest
     * @return an authenticated {@link UaaContext}
     */
    protected UaaContext authenticateAuthCode(final TokenRequest tokenRequest) {
        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setPreEstablishedRedirectUri(tokenRequest.getRedirectUri().toString());
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
        skipSslValidation(tokenRequest, template, null);
        template.getAccessToken();
        throw new UnsupportedOperationException(AUTHORIZATION_CODE +" is not yet implemented");
    }

    /**
     * Performs and authorization_code grant, but uses a token to assert the user's identity.
     * @param tokenRequest - a configured TokenRequest
     * @return an authenticated {@link UaaContext}
     */
    protected UaaContext authenticateAuthCodeWithToken(final TokenRequest tokenRequest) {
        List<OAuth2AccessTokenSupport> providers = Collections.singletonList(
            new AuthorizationCodeAccessTokenProvider() {
                @Override
                protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
                    getRestTemplate(); // force initialization
                    MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
                    return new HttpMessageConverterExtractor<OAuth2AccessToken>(CompositeAccessToken.class, Arrays.asList(converter));
                }
            }
        );
        enhanceRequestParameters(tokenRequest, providers.get(0));
        AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setPreEstablishedRedirectUri(tokenRequest.getRedirectUri().toString());
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
        skipSslValidation(tokenRequest, template, providers);
        OAuth2AccessToken token = template.getAccessToken();
        return new UaaContextImpl(tokenRequest, template, (CompositeAccessToken) token);
    }


    /**
     * Performs a {@link org.cloudfoundry.identity.client.token.GrantType#PASSWORD authentication}
     * @param tokenRequest - a configured TokenRequest
     * @return an authenticated {@link UaaContext}
     */
    protected UaaContext authenticatePassword(final TokenRequest tokenRequest) {
        List<OAuth2AccessTokenSupport> providers = Collections.singletonList(
            new ResourceOwnerPasswordAccessTokenProvider() {
                @Override
                protected ResponseExtractor<OAuth2AccessToken> getResponseExtractor() {
                    getRestTemplate(); // force initialization
                    MappingJackson2HttpMessageConverter converter = new MappingJackson2HttpMessageConverter();
                    return new HttpMessageConverterExtractor<OAuth2AccessToken>(CompositeAccessToken.class, Arrays.asList(converter));
                }
            }
        );
        enhanceRequestParameters(tokenRequest, providers.get(0));
        ResourceOwnerPasswordResourceDetails details = new ResourceOwnerPasswordResourceDetails();
        configureResourceDetails(tokenRequest, details);
        setUserCredentials(tokenRequest, details);
        setClientCredentials(tokenRequest, details);
        setRequestScopes(tokenRequest, details);
        OAuth2RestTemplate template = new OAuth2RestTemplate(details,new DefaultOAuth2ClientContext());
        skipSslValidation(tokenRequest, template, providers);
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
        skipSslValidation(request, template, null);
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

    /**
     * If the {@link TokenRequest#isSkipSslValidation()} returns true, the rest template
     * will be configured
     * @param tokenRequest
     * @param template
     */
    protected void skipSslValidation(TokenRequest tokenRequest, OAuth2RestTemplate template, List<OAuth2AccessTokenSupport> existingProviders)  {
        ClientHttpRequestFactory requestFactory = null;
        if (tokenRequest.isSkipSslValidation()) {
            requestFactory = getNoValidatingClientHttpRequestFactory();
        }
        List<OAuth2AccessTokenSupport> accessTokenProviders =
            existingProviders!=null ? existingProviders :
            Arrays.<OAuth2AccessTokenSupport>asList(
                new AuthorizationCodeAccessTokenProvider(),
                new ImplicitAccessTokenProvider(),
                new ResourceOwnerPasswordAccessTokenProvider(),
                new ClientCredentialsAccessTokenProvider()
            );
        List<AccessTokenProvider> providers = new ArrayList<>();
        for (OAuth2AccessTokenSupport provider : accessTokenProviders) {
            if (requestFactory!=null) {
                provider.setRequestFactory(requestFactory);
            }
            providers.add((AccessTokenProvider) provider);
        }
        AccessTokenProviderChain chain = new AccessTokenProviderChain(providers);
        template.setAccessTokenProvider(chain);
    }

    public static ClientHttpRequestFactory getNoValidatingClientHttpRequestFactory() {
        return getNoValidatingClientHttpRequestFactory(true);
    }
    public static ClientHttpRequestFactory getNoValidatingClientHttpRequestFactory(boolean followRedirects) {
        ClientHttpRequestFactory requestFactory;
        SSLContext sslContext;
        try {
            sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyManagementException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        //
        CloseableHttpClient httpClient =
            HttpClients.custom()
                .setSslcontext(sslContext)
                .setRedirectStrategy(
                    followRedirects ? new DefaultRedirectStrategy() : new RedirectStrategy() {
                        @Override
                        public boolean isRedirected(HttpRequest request, HttpResponse response, HttpContext context) throws ProtocolException {
                            return false;
                        }

                        @Override
                        public HttpUriRequest getRedirect(HttpRequest request, HttpResponse response, HttpContext context) throws ProtocolException {
                            return null;
                        }
                    }
                ).build();

        requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        return requestFactory;
    }

}
