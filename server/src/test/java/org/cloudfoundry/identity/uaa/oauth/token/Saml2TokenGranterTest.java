/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.UaaOauth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2AccessToken;
import org.cloudfoundry.identity.uaa.oauth.common.DefaultOAuth2RefreshToken;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.security.beans.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.security.Security;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.USER_TOKEN_REQUESTING_CLIENT_ID;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class Saml2TokenGranterTest {

    private Saml2TokenGranter granter;
    private DefaultSecurityContextAccessor mockSecurityAccessor;
    private OAuth2RequestFactory requestFactory;
    private UaaOauth2Authentication authentication;
    private TokenRequest tokenRequest;
    private UaaAuthentication userAuthentication;
    private Map<String, String> requestParameters;
    private UaaClientDetails requestingClient;
    private UaaClientDetails receivingClient;

    @BeforeEach
    void setup() {
        AuthorizationServerTokenServices tokenServices = mock(AuthorizationServerTokenServices.class);
        MultitenantClientServices clientDetailsService = mock(MultitenantClientServices.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        authentication = mock(UaaOauth2Authentication.class);
        mockSecurityAccessor = mock(DefaultSecurityContextAccessor.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);
        Security.addProvider(new org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider());

        userAuthentication = mock(UaaAuthentication.class);
        granter = new Saml2TokenGranter(
                tokenServices,
                clientDetailsService,
                requestFactory,
                mockSecurityAccessor);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        requestingClient = new UaaClientDetails("requestingId", null, "uaa.user", GRANT_TYPE_SAML2_BEARER, null);
        receivingClient = new UaaClientDetails("receivingId", null, "test.scope", GRANT_TYPE_SAML2_BEARER, null);
        when(clientDetailsService.loadClientByClientId(eq(requestingClient.getClientId()), anyString())).thenReturn(requestingClient);
        when(clientDetailsService.loadClientByClientId(eq(receivingClient.getClientId()), anyString())).thenReturn(receivingClient);
        when(mockSecurityAccessor.isUser()).thenReturn(true);
        requestParameters = new HashMap<>();
        requestParameters.put(USER_TOKEN_REQUESTING_CLIENT_ID, requestingClient.getClientId());
        requestParameters.put(GRANT_TYPE, GRANT_TYPE_SAML2_BEARER);
        requestParameters.put(CLIENT_ID, receivingClient.getClientId());
        tokenRequest = new PublicTokenRequest();
        tokenRequest.setRequestParameters(requestParameters);
    }

    @AfterEach
    void teardown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void notAuthenticated() {
        when(authentication.isAuthenticated()).thenReturn(false);
        assertThat(granter.validateRequest(tokenRequest))
                .isSameAs(authentication);
    }

    @Test
    void notAUserAuthentication() {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getUserAuthentication()).thenReturn(null);
        assertThat(granter.validateRequest(tokenRequest))
                .isSameAs(authentication);
    }

    @Test
    void invalidGrantType() {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        requestParameters.put(GRANT_TYPE, "password");
        tokenRequest.setRequestParameters(requestParameters);

        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessage("Invalid grant type");
    }

    @Test
    void noUserAuthentication() {
        SecurityContextHolder.getContext().setAuthentication(authentication);
        when(mockSecurityAccessor.isUser()).thenReturn(false);

        assertThatThrownBy(() -> granter.validateRequest(tokenRequest))
                .isInstanceOf(InvalidGrantException.class)
                .hasMessage("User authentication not found");
    }

    @Test
    void noGrantType() {
        assertThatThrownBy(() -> missingParameter(GRANT_TYPE))
                .isInstanceOf(InvalidGrantException.class);
    }

    @Test
    void happyDay() {
        assertThatNoException().isThrownBy(() -> missingParameter("non existent"));
    }

    @Test
    void ensureThatAccessTokenIsDeletedAndModified() {
        String tokenId = "access_token";
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(tokenId);
        DefaultOAuth2RefreshToken refreshToken = new DefaultOAuth2RefreshToken("refresh_token");

        Map<String, Object> info = new HashMap<>(token.getAdditionalInformation());
        assertThat(info).isNotNull();
        info.put(JTI, token.getValue());
        token.setAdditionalInformation(info);
        token.setRefreshToken(refreshToken);
        token.setExpiration(new Date());
    }

    @Test
    void grant() {
        tokenRequest.setGrantType(requestParameters.get(GRANT_TYPE));
        assertThatNoException().isThrownBy(() -> granter.grant(GRANT_TYPE, tokenRequest));
    }

    @Test
    void oauth2AuthenticationWithEmptyAllowed() {
        OAuth2Request myReq = new OAuth2Request(requestParameters, receivingClient.getClientId(), receivingClient.getAuthorities(), true, receivingClient.getScope(), receivingClient.getResourceIds(), null, null, null);
        UaaClientDetails myClient = new UaaClientDetails(requestingClient);
        List<String> allowedProviders = new LinkedList<>();
        Map<String, Object> additionalInformation = new LinkedHashMap<>();
        Collection<GrantedAuthority> me = AuthorityUtils.commaSeparatedStringToAuthorityList("openid,foo.bar,uaa.user,one.read");
        Saml2TokenGranter mockedGranter = mock(Saml2TokenGranter.class);
        when(mockedGranter.validateRequest(tokenRequest)).thenReturn(userAuthentication);
        when(mockedGranter.getOAuth2Authentication(myClient, tokenRequest)).thenCallRealMethod();
        myClient.setScope(StringUtils.commaDelimitedListToSet("openid,foo.bar"));
        additionalInformation.put(ClientConstants.ALLOWED_PROVIDERS, allowedProviders);
        myClient.setAdditionalInformation(additionalInformation);
        when(userAuthentication.getAuthorities()).thenReturn(me);
        when(requestFactory.createOAuth2Request(receivingClient, tokenRequest)).thenReturn(myReq);
        granter.getOAuth2Authentication(myClient, tokenRequest);
    }

    @Test
    void missingTokenRequest() {
        assertThatThrownBy(() -> granter.validateRequest(null))
                .isInstanceOf(InvalidGrantException.class);
    }

    protected void missingParameter(String parameter) {
        when(authentication.isAuthenticated()).thenReturn(true);
        when(authentication.getUserAuthentication()).thenReturn(null);
        when(authentication.getUserAuthentication()).thenReturn(userAuthentication);
        when(userAuthentication.isAuthenticated()).thenReturn(true);
        requestParameters.remove(parameter);
        tokenRequest = new PublicTokenRequest();
        tokenRequest.setClientId(receivingClient.getClientId());
        tokenRequest.setRequestParameters(requestParameters);
        tokenRequest.setGrantType(requestParameters.get(GRANT_TYPE));
        granter.validateRequest(tokenRequest);
    }

    public static class PublicTokenRequest extends TokenRequest {
        // empty
    }
}
