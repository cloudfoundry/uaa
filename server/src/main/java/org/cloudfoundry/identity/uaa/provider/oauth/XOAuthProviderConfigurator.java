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

import com.fasterxml.jackson.core.type.TypeReference;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.cache.UrlContentCache;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.RestTemplateFactory;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;

public class XOAuthProviderConfigurator implements IdentityProviderProvisioning {

    private static Log log = LogFactory.getLog(XOAuthProviderConfigurator.class);

    private final IdentityProviderProvisioning providerProvisioning;
    private final UrlContentCache contentCache;
    private final RestTemplateFactory restTemplateFactory;

    public XOAuthProviderConfigurator(IdentityProviderProvisioning providerProvisioning,
                                      UrlContentCache contentCache,
                                      RestTemplateFactory restTemplateFactory) {
        this.providerProvisioning = providerProvisioning;
        this.contentCache = contentCache;
        this.restTemplateFactory = restTemplateFactory;
    }

    protected OIDCIdentityProviderDefinition overlay(OIDCIdentityProviderDefinition definition) {
        if (definition.getDiscoveryUrl() == null) {
            return definition;
        }

        byte[] oidcJson = contentCache.getUrlContent(definition.getDiscoveryUrl().toString(), restTemplateFactory.getRestTemplate(definition.isSkipSslValidation()));
        Map<String,Object> oidcConfig = JsonUtils.readValue(oidcJson, new TypeReference<Map<String, Object>>() {});

        OIDCIdentityProviderDefinition overlayedDefinition = null;
        try {
            overlayedDefinition = (OIDCIdentityProviderDefinition) definition.clone();
            URL authorizationEndpoint = new URL((String) oidcConfig.get("authorization_endpoint"));
            URL userinfoEndpoint = new URL((String) oidcConfig.get("userinfo_endpoint"));
            URL tokenEndpoint = new URL((String) oidcConfig.get("token_endpoint"));
            URL tokenKeyUrl = new URL((String) oidcConfig.get("jwks_uri"));
            String issuer = (String) oidcConfig.get("issuer");
            overlayedDefinition.setAuthUrl(ofNullable(overlayedDefinition.getAuthUrl()).orElse(authorizationEndpoint));
            overlayedDefinition.setUserInfoUrl(ofNullable(overlayedDefinition.getUserInfoUrl()).orElse(userinfoEndpoint));
            overlayedDefinition.setTokenUrl(ofNullable(overlayedDefinition.getTokenUrl()).orElse(tokenEndpoint));
            overlayedDefinition.setIssuer(ofNullable(overlayedDefinition.getIssuer()).orElse(issuer));
            overlayedDefinition.setTokenKeyUrl(ofNullable(overlayedDefinition.getTokenKeyUrl()).orElse(tokenKeyUrl));
        } catch (MalformedURLException e) {
            throw new IllegalStateException(e);
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException(e);
        }

        return overlayedDefinition;
    }

    public String getCompleteAuthorizationURI(String alias, String baseURL, AbstractXOAuthIdentityProviderDefinition definition) {
        try {
            String authUrlBase;
            if(definition instanceof OIDCIdentityProviderDefinition) {
                authUrlBase = overlay((OIDCIdentityProviderDefinition) definition).getAuthUrl().toString();
            } else {
                authUrlBase = definition.getAuthUrl().toString();
            }
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

    @Override
    public IdentityProvider create(IdentityProvider identityProvider, String zoneId) {
        return providerProvisioning.create(identityProvider, zoneId);
    }

    @Override
    public IdentityProvider update(IdentityProvider identityProvider, String zoneId) {
        return providerProvisioning.update(identityProvider, zoneId);
    }

    @Override
    public IdentityProvider retrieve(String id, String zoneId) {
        IdentityProvider p = providerProvisioning.retrieve(id, zoneId);
        if (p!=null && p.getType().equals(OIDC10)) {
            p.setConfig(overlay((OIDCIdentityProviderDefinition) p.getConfig()));
        }
        return p;
    }

    @Override
    public List<IdentityProvider> retrieveActive(String zoneId) {
        return retrieveAll(true, zoneId);
    }

    public IdentityProvider retrieveByIssuer(String issuer, String zoneId) throws IncorrectResultSizeDataAccessException {
        List<IdentityProvider> providers = retrieveAll(true, zoneId)
            .stream()
            .filter(p -> OIDC10.equals(p.getType()) &&
                    issuer.equals(((OIDCIdentityProviderDefinition)p.getConfig()).getIssuer()))
            .collect(Collectors.toList());
        if (providers.isEmpty()) {
            throw new IncorrectResultSizeDataAccessException(String.format("Active provider with issuer[%s] not found", issuer), 1);
        } else if (providers.size() > 1) {
            throw new IncorrectResultSizeDataAccessException(String.format("Duplicate providers with issuer[%s] not found", issuer), 1);
        }
        return providers.get(0);
    }

    @Override
    public List<IdentityProvider> retrieveAll(boolean activeOnly, String zoneId) {
        final List<String> types = Arrays.asList(OAUTH20, OIDC10);
        List<IdentityProvider> providers = providerProvisioning.retrieveAll(activeOnly, zoneId);
        List<IdentityProvider> overlayedProviders = new ArrayList<>();
        ofNullable(providers).orElse(emptyList()).stream()
            .filter(p -> types.contains(p.getType()))
            .forEach(p -> {
                if (p.getType().equals(OIDC10)) {
                    try {
                        OIDCIdentityProviderDefinition overlayedDefinition = overlay((OIDCIdentityProviderDefinition) p.getConfig());
                        p.setConfig(overlayedDefinition);
                    } catch (Exception e) {
                        log.error("Identity provider excluded from login page due to a problem.", e);
                        return;
                    }
                }
                overlayedProviders.add(p);
            });
        return overlayedProviders;
    }

    @Override
    public IdentityProvider retrieveByOrigin(String origin, String zoneId) {
        IdentityProvider p = providerProvisioning.retrieveByOrigin(origin, zoneId);
        if (p!=null && p.getType().equals(OIDC10)) {
            p.setConfig(overlay((OIDCIdentityProviderDefinition) p.getConfig()));
        }
        return p;
    }
}
