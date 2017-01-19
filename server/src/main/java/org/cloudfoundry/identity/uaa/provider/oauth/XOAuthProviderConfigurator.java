/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  *******************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;

public class XOAuthProviderConfigurator {


    private final IdentityProviderProvisioning providerProvisioning;

    public XOAuthProviderConfigurator(IdentityProviderProvisioning providerProvisioning) {
        this.providerProvisioning = providerProvisioning;
    }

    public List<IdentityProvider> getActiveXOAuthProviders(String zoneId) {
        final List<String> types = Arrays.asList(OAUTH20, OIDC10);
        List<IdentityProvider> providers = providerProvisioning.retrieveAll(true, zoneId);
        return providers.stream().filter(p -> types.contains(p.getType())).collect(Collectors.toList());
    }

    protected OIDCIdentityProviderDefinition overlay(OIDCIdentityProviderDefinition definition) {
        return null;
    }

    public String getCompleteAuthorizationURI(String alias, String baseURL, AbstractXOAuthIdentityProviderDefinition definition) {
        try {
            String authUrlBase = definition.getAuthUrl().toString();
            String queryAppendDelimiter = authUrlBase.contains("?") ? "&" : "?";
            List<String> query = new ArrayList<>();
            query.add("client_id=" + definition.getRelyingPartyId());
            query.add("response_type="+ URLEncoder.encode(definition.getResponseType(), "UTF-8"));
            query.add("redirect_uri=" + URLEncoder.encode(baseURL + "/login/callback/" + alias, "UTF-8"));
            if (definition.getScopes() != null && !definition.getScopes().isEmpty()) {
                query.add("scope=" + URLEncoder.encode(String.join(" ", definition.getScopes()), "UTF-8"));
            }
            if (OIDCIdentityProviderDefinition.class.equals(definition.getParameterizedClass())) {
                final RandomValueStringGenerator nonceGenerator = new RandomValueStringGenerator(12);
                query.add("nonce=" + nonceGenerator.generate());
            }
            String queryString = String.join("&", query);
            return authUrlBase + queryAppendDelimiter + queryString;
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

}
