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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.security.DefaultSecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;

public class Saml2TokenGranter extends AbstractTokenGranter {

    private static final Log logger = LogFactory.getLog(Saml2TokenGranter.class);


    public Saml2TokenGranter(AuthorizationServerTokenServices tokenServices,
                             ClientServicesExtension clientDetailsService,
                             OAuth2RequestFactory requestFactory) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE_SAML2_BEARER);
    }

    @Override
    public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
        TokenRequest adjusted = new TokenRequest(tokenRequest.getRequestParameters(), tokenRequest.getClientId(),
                tokenRequest.getScope(), tokenRequest.getGrantType());
        return super.grant(grantType, adjusted);
    }


    @SuppressWarnings("unchecked")
    protected Authentication validateRequest(TokenRequest request) {
        // things to validate
        if(request == null || request.getRequestParameters() == null) {
            throw new InvalidGrantException("Missing token request object");
        }
        if(request.getRequestParameters().get("grant_type") == null) {
            throw new InvalidGrantException("Missing grant type");
        }
        if(!GRANT_TYPE_SAML2_BEARER.equals(request.getRequestParameters().get("grant_type"))) {
            throw new InvalidGrantException("Invalid grant type");
        }
        // parse the XML to Assertion
        if (new DefaultSecurityContextAccessor().isUser()) {
            return SecurityContextHolder.getContext().getAuthentication();
        }

        throw new InvalidGrantException("User authentication not found");
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
        Authentication userAuth = validateRequest(tokenRequest);
        OAuth2Request storedOAuth2Request = getRequestFactory().createOAuth2Request(client, tokenRequest);
        return new OAuth2Authentication(storedOAuth2Request, userAuth);
    }

    @Override
    protected OAuth2RequestFactory getRequestFactory() {
        return super.getRequestFactory();
    }

    @Override
    protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
        return super.getAccessToken(client, tokenRequest);
    }

}