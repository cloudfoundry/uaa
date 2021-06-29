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

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderWrapper;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.RawExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.ATTRIBUTE_MAPPINGS;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.STORE_CUSTOM_ATTRIBUTES_NAME;
import static org.springframework.util.StringUtils.hasText;

public class OauthIDPWrapperFactoryBean {
    private Map<String, AbstractExternalOAuthIdentityProviderDefinition> oauthIdpDefinitions = new HashMap<>();
    private List<IdentityProviderWrapper> providers = new LinkedList<>();

    public OauthIDPWrapperFactoryBean(Map<String, Map> definitions) {
        if (definitions != null) {
            for (String alias : definitions.keySet()) {
                Map<String, Object> idpDefinitionMap = definitions.get(alias);
                AbstractExternalOAuthIdentityProviderDefinition rawDef;
                try {
                    IdentityProvider provider = new IdentityProvider();
                    String type = (String) idpDefinitionMap.get("type");
                    if(OAUTH20.equalsIgnoreCase(type)) {
                        RawExternalOAuthIdentityProviderDefinition oauthIdentityProviderDefinition = new RawExternalOAuthIdentityProviderDefinition();
                        oauthIdentityProviderDefinition.setCheckTokenUrl(idpDefinitionMap.get("checkTokenUrl") == null ? null : new URL((String) idpDefinitionMap.get("checkTokenUrl")));
                        setCommonProperties(idpDefinitionMap, oauthIdentityProviderDefinition);
                        oauthIdpDefinitions.put(alias, oauthIdentityProviderDefinition);
                        rawDef = oauthIdentityProviderDefinition;
                        provider.setType(OriginKeys.OAUTH20);
                    }
                    else if(OIDC10.equalsIgnoreCase(type)) {
                        OIDCIdentityProviderDefinition oidcIdentityProviderDefinition = new OIDCIdentityProviderDefinition();
                        setCommonProperties(idpDefinitionMap, oidcIdentityProviderDefinition);
                        oidcIdentityProviderDefinition.setUserInfoUrl(idpDefinitionMap.get("userInfoUrl") == null ? null : new URL((String) idpDefinitionMap.get("userInfoUrl")));
                        oidcIdentityProviderDefinition.setPasswordGrantEnabled(idpDefinitionMap.get("passwordGrantEnabled") == null ? false : (boolean) idpDefinitionMap.get("passwordGrantEnabled"));
                        oidcIdentityProviderDefinition.setSetForwardHeader(idpDefinitionMap.get("setForwardHeader") == null ? false : (boolean) idpDefinitionMap.get("passwordGrantEnabled"));
                        oidcIdentityProviderDefinition.setPrompts((List<Prompt>) idpDefinitionMap.get("prompts"));
                        oauthIdpDefinitions.put(alias, oidcIdentityProviderDefinition);
                        rawDef = oidcIdentityProviderDefinition;
                        provider.setType(OriginKeys.OIDC10);
                    } else {
                        throw new IllegalArgumentException("Unknown type for provider. Type must be oauth2.0 or oidc1.0. (Was " + type + ")");
                    }
                    boolean override = true;
                    if (idpDefinitionMap.get("override") != null) {
                        override = (boolean) idpDefinitionMap.get("override");
                    }

                    IdentityProviderWrapper wrapper = getIdentityProviderWrapper(alias, rawDef, provider, override);

                    providers.add(wrapper);
                } catch (MalformedURLException e) {
                    throw new IllegalArgumentException("OAuth/OIDC Provider Configuration - URL is malformed.", e);
                }
            }



        }
    }

    public static IdentityProviderWrapper getIdentityProviderWrapper(String origin, AbstractExternalOAuthIdentityProviderDefinition rawDef, IdentityProvider provider, boolean override) {
        provider.setOriginKey(origin);
        provider.setName("UAA Oauth Identity Provider["+provider.getOriginKey()+"]");
        provider.setActive(true);
        try {
            provider.setConfig(rawDef);
        } catch (JsonUtils.JsonUtilException x) {
            throw new RuntimeException("Non serializable Oauth config");
        }
        IdentityProviderWrapper wrapper = new IdentityProviderWrapper(provider);
        wrapper.setOverride(override);
        return wrapper;
    }

    protected void setCommonProperties(Map<String, Object> idpDefinitionMap, AbstractExternalOAuthIdentityProviderDefinition idpDefinition) {
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
        idpDefinition.setUserPropagationParameter((String) idpDefinitionMap.get("userPropagationParameter"));
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
                idpDefinition.setUserInfoUrl(idpDefinitionMap.get("userInfoUrl") == null ? null : new URL((String) idpDefinitionMap.get("userInfoUrl")));
            }
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("URL is malformed.", e);
        }
        if (idpDefinitionMap.get("clientAuthInBody") instanceof Boolean) {
            idpDefinition.setClientAuthInBody((boolean)idpDefinitionMap.get("clientAuthInBody"));
        }
    }

    public Map<String, AbstractExternalOAuthIdentityProviderDefinition> getOauthIdpDefinitions() {
        return oauthIdpDefinitions;
    }

    public List<IdentityProviderWrapper> getProviders() {
        return providers;
    }

    public void setOauthIdpDefinitions(Map<String, AbstractExternalOAuthIdentityProviderDefinition> oauthIdpDefinitions) {
        this.oauthIdpDefinitions = oauthIdpDefinitions;
    }
}
