/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.ATTRIBUTE_MAPPINGS;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.STORE_CUSTOM_ATTRIBUTES_NAME;
import static org.springframework.util.StringUtils.hasText;

public class OauthIdentityProviderDefinitionFactoryBean {
    private Map<String,AbstractXOAuthIdentityProviderDefinition> oauthIdpDefinitions = new HashMap<>();

    public OauthIdentityProviderDefinitionFactoryBean(Map<String, Map> definitions) {
        if (definitions != null) {
            for (String alias : definitions.keySet()) {
                Map<String, Object> idpDefinitionMap = definitions.get(alias);
                try {
                    String type = (String) idpDefinitionMap.get("type");
                    if(OAUTH20.equalsIgnoreCase(type)) {
                        RawXOAuthIdentityProviderDefinition oauthIdentityProviderDefinition = new RawXOAuthIdentityProviderDefinition();
                        oauthIdentityProviderDefinition.setCheckTokenUrl(idpDefinitionMap.get("checkTokenUrl") == null ? null : new URL((String) idpDefinitionMap.get("checkTokenUrl")));
                        setCommonProperties(idpDefinitionMap, oauthIdentityProviderDefinition);
                        oauthIdpDefinitions.put(alias, oauthIdentityProviderDefinition);
                    }
                    else if(OIDC10.equalsIgnoreCase(type)) {
                        OIDCIdentityProviderDefinition oidcIdentityProviderDefinition = new OIDCIdentityProviderDefinition();
                        setCommonProperties(idpDefinitionMap, oidcIdentityProviderDefinition);
                        oidcIdentityProviderDefinition.setUserInfoUrl(idpDefinitionMap.get("userInfoUrl") == null ? null : new URL((String) idpDefinitionMap.get("userInfoUrl")));
                        oauthIdpDefinitions.put(alias, oidcIdentityProviderDefinition);
                    } else {
                        throw new IllegalArgumentException("Unknown type for provider. Type must be oauth2.0 or oidc1.0. (Was " + type + ")");
                    }
                }
                catch (MalformedURLException e) {
                    throw new IllegalArgumentException("URL is malformed.", e);
                }
            }
        }
    }

    protected void setCommonProperties(Map<String, Object> idpDefinitionMap, AbstractXOAuthIdentityProviderDefinition idpDefinition) {
        idpDefinition.setLinkText((String)idpDefinitionMap.get("linkText"));
        idpDefinition.setRelyingPartyId((String) idpDefinitionMap.get("relyingPartyId"));
        idpDefinition.setRelyingPartySecret((String) idpDefinitionMap.get("relyingPartySecret"));
        idpDefinition.setEmailDomain((List<String>) idpDefinitionMap.get("emailDomain"));
        idpDefinition.setShowLinkText(idpDefinitionMap.get("showLinkText") == null ? true : (boolean) idpDefinitionMap.get("showLinkText"));
        idpDefinition.setAddShadowUserOnLogin(idpDefinitionMap.get("addShadowUserOnLogin") == null ? true : (boolean) idpDefinitionMap.get("addShadowUserOnLogin"));
        idpDefinition.setStoreCustomAttributes(idpDefinitionMap.get(STORE_CUSTOM_ATTRIBUTES_NAME) == null ? true : (boolean) idpDefinitionMap.get(STORE_CUSTOM_ATTRIBUTES_NAME));
        idpDefinition.setSkipSslValidation(idpDefinitionMap.get("skipSslValidation") == null ? false : (boolean) idpDefinitionMap.get("skipSslValidation"));
        idpDefinition.setTokenKey((String) idpDefinitionMap.get("tokenKey"));
        idpDefinition.setIssuer((String) idpDefinitionMap.get("issuer"));
        idpDefinition.setAttributeMappings((Map<String, Object>) idpDefinitionMap.get(ATTRIBUTE_MAPPINGS));
        idpDefinition.setScopes((List<String>) idpDefinitionMap.get("scopes"));
        String responseType = (String) idpDefinitionMap.get("responseType");
        if (hasText(responseType)) {
            idpDefinition.setResponseType(responseType);
        }
        String discoveryUrl = (String) idpDefinitionMap.get("discoveryUrl");
        try {
            if (hasText(discoveryUrl) && idpDefinition instanceof OIDCIdentityProviderDefinition) {
                ((OIDCIdentityProviderDefinition) idpDefinition).setDiscoveryUrl(new URL(discoveryUrl));
            } else {
                idpDefinition.setAuthUrl(new URL((String) idpDefinitionMap.get("authUrl")));
                idpDefinition.setTokenKeyUrl(idpDefinitionMap.get("tokenKeyUrl") == null ? null : new URL((String) idpDefinitionMap.get("tokenKeyUrl")));
                idpDefinition.setTokenUrl(new URL((String) idpDefinitionMap.get("tokenUrl")));
            }
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("URL is malformed.", e);
        }
    }

    public Map<String,AbstractXOAuthIdentityProviderDefinition> getOauthIdpDefinitions() {
        return oauthIdpDefinitions;
    }

    public void setOauthIdpDefinitions(Map<String,AbstractXOAuthIdentityProviderDefinition> oauthIdpDefinitions) {
        this.oauthIdpDefinitions = oauthIdpDefinitions;
    }
}
