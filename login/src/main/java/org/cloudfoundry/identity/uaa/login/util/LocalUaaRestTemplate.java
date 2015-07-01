/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login.util;

import org.apache.http.conn.ssl.SSLContextBuilder;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.oauth.token.UaaTokenServices;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import javax.net.ssl.SSLContext;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class LocalUaaRestTemplate extends OAuth2RestTemplate implements InitializingBean {
    protected UaaTokenServices tokenServices;
    protected String clientId;
    protected ClientDetailsService clientDetailsService;
    protected boolean verifySsl = true;

    public LocalUaaRestTemplate(OAuth2ProtectedResourceDetails resource) {
        super(resource);
    }

    public LocalUaaRestTemplate(OAuth2ProtectedResourceDetails resource, OAuth2ClientContext context) {
        super(resource, context);
    }

    @Override
    protected OAuth2AccessToken acquireAccessToken(OAuth2ClientContext oauth2Context) throws UserRedirectRequiredException {
        ClientDetails client = clientDetailsService.loadClientByClientId(getClientId());
        Set<String> scopes = new HashSet<>();
        for (GrantedAuthority authority : client.getAuthorities()) {
            scopes.add(authority.getAuthority());
        }
        Set<String> resourceIds = new HashSet<>();
        resourceIds.add(Origin.UAA);
        Set<String> responseTypes = new HashSet<>();
        responseTypes.add("token");
        Map<String,String> requestParameters = new HashMap<>();
        requestParameters.put(OAuth2Utils.CLIENT_ID, "login");
        requestParameters.put(OAuth2Utils.GRANT_TYPE, "client_credentials");
        OAuth2Request request = new OAuth2Request(
            requestParameters,
            "login",
            (Collection<? extends GrantedAuthority>)Collections.EMPTY_SET,
            true,
            scopes,
            resourceIds,
            null,
            responseTypes,
            Collections.EMPTY_MAP);
        OAuth2Authentication authentication = new OAuth2Authentication(request, null);
        OAuth2AccessToken result = tokenServices.createAccessToken(authentication);
        oauth2Context.setAccessToken(result);
        return result;
    }

    public UaaTokenServices getTokenServices() {
        return tokenServices;
    }

    public void setTokenServices(UaaTokenServices tokenServices) {
        this.tokenServices = tokenServices;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public ClientDetailsService getClientDetailsService() {
        return clientDetailsService;
    }

    public void setClientDetailsService(ClientDetailsService clientDetailsService) {
        this.clientDetailsService = clientDetailsService;
    }

    public boolean isVerifySsl() {
        return verifySsl;
    }

    public void setVerifySsl(boolean verifySsl) {
        this.verifySsl = verifySsl;
    }

    protected void skipSslValidation() throws KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
        CloseableHttpClient httpClient = HttpClients.custom().setSslcontext(sslContext).build();
        ClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        this.setRequestFactory(requestFactory);
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        if (tokenServices==null) {
            throw new NullPointerException("tokenServices property is null!");
        }
        if (clientId==null) {
            throw new NullPointerException("clientId property is null!");
        }
        if (clientDetailsService==null) {
            throw new NullPointerException("clientDetailsService property is null!");
        }
        if (!isVerifySsl()) {
            skipSslValidation();
        }
    }
}
