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

import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.provider.TokenRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AbstractTokenGranter;
import org.cloudfoundry.identity.uaa.oauth.provider.token.AuthorizationServerTokenServices;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidGrantException;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;

public class Saml2TokenGranter extends AbstractTokenGranter {

    private static final Logger logger = LoggerFactory.getLogger(Saml2TokenGranter.class);
    private final SecurityContextAccessor securityContextAccessor;

    public Saml2TokenGranter(final AuthorizationServerTokenServices tokenServices,
            final MultitenantClientServices clientDetailsService,
            final OAuth2RequestFactory requestFactory,
            final SecurityContextAccessor securityContextAccessor) {
        super(tokenServices, clientDetailsService, requestFactory, GRANT_TYPE_SAML2_BEARER);
        this.securityContextAccessor = securityContextAccessor;
    }

    protected Authentication validateRequest(TokenRequest request) {
        // things to validate
        if (request == null || request.getRequestParameters() == null) {
            throw new InvalidGrantException("Missing token request object");
        }
        if (request.getRequestParameters().get("grant_type") == null) {
            throw new InvalidGrantException("Missing grant type");
        }
        if (!GRANT_TYPE_SAML2_BEARER.equals(request.getRequestParameters().get("grant_type"))) {
            throw new InvalidGrantException("Invalid grant type");
        }
        // parse the XML to Assertion
        if (securityContextAccessor.isUser()) {
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
}