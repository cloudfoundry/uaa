/*
 * *****************************************************************************
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

import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
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
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.ATTRIBUTE_MAPPINGS;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.STORE_CUSTOM_ATTRIBUTES_NAME;
import static org.springframework.util.StringUtils.hasText;

public class OauthIDPWrapperFactoryBean {
    private Map<String, AbstractExternalOAuthIdentityProviderDefinition> oauthIdpDefinitions = new HashMap<>();
    private final List<IdentityProviderWrapper> providers = new LinkedList<>();

    public OauthIDPWrapperFactoryBean(Map<String, Map> definitions) {
        if (definitions != null) {
            for (String alias : definitions.keySet()) {
                Map<String, Object> idpDefinitionMap = definitions.get(alias);
                AbstractExternalOAuthIdentityProviderDefinition rawDef;
                try {
                    IdentityProvider provider = new IdentityProvider();
                    String type = (String) idpDefinitionMap.get("type");
                    if (OAUTH20.equalsIgnoreCase(type)) {
                        RawExternalOAuthIdentityProviderDefinition oauthIdentityProviderDefinition = new RawExternalOAuthIdentityProviderDefinition();
                        oauthIdentityProviderDefinition.setCheckTokenUrl(idpDefinitionMap.get("checkTokenUrl") == null ? null : new URL((String) idpDefinitionMap.get("checkTokenUrl")));
                        setCommonProperties(idpDefinitionMap, oauthIdentityProviderDefinition);
                        oauthIdpDefinitions.put(alias, oauthIdentityProviderDefinition);
                        rawDef = oauthIdentityProviderDefinition;
                        provider.setType(OriginKeys.OAUTH20);
                    } else if (OIDC10.equalsIgnoreCase(type)) {
                        rawDef = getExternalOIDCIdentityProviderDefinition(alias, idpDefinitionMap, provider);
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

    /**
     * Get IdP configuration map. The properties are documented either via
     * https://docs.cloudfoundry.org/api/uaa/index.html#oauth-oidc -> create OAuth/OIDC Identity Provider
     * or class
     * #org.cloudfoundry.identity.uaa.mock.providers.IdentityProviderEndpointDocs
     */
    private AbstractExternalOAuthIdentityProviderDefinition getExternalOIDCIdentityProviderDefinition(String alias,
            Map<String, Object> idpDefinitionMap, IdentityProvider provider) throws MalformedURLException {
        AbstractExternalOAuthIdentityProviderDefinition rawDef;
        OIDCIdentityProviderDefinition oidcIdentityProviderDefinition = new OIDCIdentityProviderDefinition();
        setCommonProperties(idpDefinitionMap, oidcIdentityProviderDefinition);
        oidcIdentityProviderDefinition.setUserInfoUrl(idpDefinitionMap.get("userInfoUrl") == null ? null : new URL((String) idpDefinitionMap.get("userInfoUrl")));
        oidcIdentityProviderDefinition.setPasswordGrantEnabled(
                idpDefinitionMap.get("passwordGrantEnabled") == null ? false : (boolean) idpDefinitionMap.get("passwordGrantEnabled"));
        oidcIdentityProviderDefinition.setSetForwardHeader(idpDefinitionMap.get("setForwardHeader") == null ? false : (boolean) idpDefinitionMap.get("setForwardHeader"));
        oidcIdentityProviderDefinition.setTokenExchangeEnabled(Optional.ofNullable(idpDefinitionMap.get("tokenExchangeEnabled")).filter(Boolean.class::isInstance).map(Boolean.class::cast).orElse(false));
        oidcIdentityProviderDefinition.setPrompts((List<Prompt>) idpDefinitionMap.get("prompts"));
        setJwtClientAuthentication(idpDefinitionMap, oidcIdentityProviderDefinition);
        oauthIdpDefinitions.put(alias, oidcIdentityProviderDefinition);
        rawDef = oidcIdentityProviderDefinition;
        provider.setType(OriginKeys.OIDC10);
        return rawDef;
    }

    private static void setJwtClientAuthentication(Map<String, Object> map, OIDCIdentityProviderDefinition definition) {
        Object jwtClientAuthDetails = getJwtClientAuthenticationDetails(map, List.of("jwtClientAuthentication", "jwtclientAuthentication"));
        if (jwtClientAuthDetails != null) {
            if (jwtClientAuthDetails instanceof Boolean boolValue) {
                if (boolValue.booleanValue()) {
                    definition.setJwtClientAuthentication(Collections.emptyMap());
                }
            } else if (jwtClientAuthDetails instanceof Map) {
                definition.setJwtClientAuthentication(jwtClientAuthDetails);
            }
        }
    }

    private static Object getJwtClientAuthenticationDetails(Map<String, Object> uaaYamlMap, List<String> entryInUaaYaml) {
        return entryInUaaYaml.stream().filter(e -> uaaYamlMap.get(e) != null).findFirst().map(uaaYamlMap::get).orElse(null);
    }

    public static IdentityProviderWrapper getIdentityProviderWrapper(String origin, AbstractExternalOAuthIdentityProviderDefinition rawDef, IdentityProvider provider, boolean override) {
        provider.setOriginKey(origin);
        provider.setName("UAA Oauth Identity Provider[" + provider.getOriginKey() + "]");
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
        idpDefinition.setLinkText((String) idpDefinitionMap.get("linkText"));
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
        idpDefinition.setGroupMappingMode(parseExternalGroupMappingMode(idpDefinitionMap.get("groupMappingMode")));
        String responseType = (String) idpDefinitionMap.get("responseType");
        if (hasText(responseType)) {
            idpDefinition.setResponseType(responseType);
        }
        String discoveryUrl = (String) idpDefinitionMap.get("discoveryUrl");
        try {
            OIDCIdentityProviderDefinition oidcIdentityProviderDefinition = null;
            if (idpDefinition instanceof OIDCIdentityProviderDefinition definition) {
                oidcIdentityProviderDefinition = definition;
                oidcIdentityProviderDefinition.setAdditionalAuthzParameters(parseAdditionalParameters(idpDefinitionMap));

                if (hasText(discoveryUrl)) {
                    oidcIdentityProviderDefinition.setDiscoveryUrl(new URL(discoveryUrl));
                }
            }

            if (oidcIdentityProviderDefinition == null || !hasText(discoveryUrl)) {
                idpDefinition.setAuthUrl(new URL((String) idpDefinitionMap.get("authUrl")));
                idpDefinition.setTokenKeyUrl(idpDefinitionMap.get("tokenKeyUrl") == null ? null : new URL((String) idpDefinitionMap.get("tokenKeyUrl")));
                idpDefinition.setTokenUrl(new URL((String) idpDefinitionMap.get("tokenUrl")));
                idpDefinition.setUserInfoUrl(idpDefinitionMap.get("userInfoUrl") == null ? null : new URL((String) idpDefinitionMap.get("userInfoUrl")));
                idpDefinition.setLogoutUrl(idpDefinitionMap.get("logoutUrl") == null ? null : new URL((String) idpDefinitionMap.get("logoutUrl")));
            }
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("URL is malformed.", e);
        }
        if (idpDefinitionMap.get("clientAuthInBody") instanceof Boolean) {
            idpDefinition.setClientAuthInBody((boolean) idpDefinitionMap.get("clientAuthInBody"));
        }
        if (idpDefinitionMap.get("performRpInitiatedLogout") instanceof Boolean) {
            idpDefinition.setPerformRpInitiatedLogout((boolean) idpDefinitionMap.get("performRpInitiatedLogout"));
        }
        if (idpDefinitionMap.get("cacheJwks") instanceof Boolean) {
            idpDefinition.setCacheJwks((boolean) idpDefinitionMap.get("cacheJwks"));
        }
        if (idpDefinitionMap.get("authMethod") instanceof String definedAuthMethod) {
            if (ClientAuthentication.isMethodSupported(definedAuthMethod)) {
                idpDefinition.setAuthMethod(definedAuthMethod);
            } else {
                throw new IllegalArgumentException("Invalid IdP authentication method");
            }
        }
    }

    private static Map<String, String> parseAdditionalParameters(Map<String, Object> idpDefinitionMap) {
        Map<String, Object> additionalParameters = (Map<String, Object>) idpDefinitionMap.get("additionalAuthzParameters");
        if (additionalParameters != null) {
            Map<String, String> additionalQueryParameters = new HashMap<>();
            for (Map.Entry<String, Object> entry : additionalParameters.entrySet()) {
                String keyEntry = entry.getKey().toLowerCase(Locale.ROOT);
                String value = null;
                if (entry.getValue() instanceof Integer) {
                    value = String.valueOf(entry.getValue());
                } else if (entry.getValue() instanceof String) {
                    value = (String) entry.getValue();
                }
                // accept only custom parameters, filter out standard parameters
                if (value == null || ExternalOAuthIdentityProviderConfigValidator.isOAuthStandardParameter(keyEntry)) {
                    continue;
                }
                additionalQueryParameters.put(entry.getKey(), value);
            }
            return additionalQueryParameters;
        }
        return null;
    }

    /* parse with null check because default should be null */
    private AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode parseExternalGroupMappingMode(Object mode) {
        if (mode instanceof String) {
            if (AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.AS_SCOPES.toString().equals(mode)) {
                return AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.AS_SCOPES;
            }
        }
        return AbstractExternalOAuthIdentityProviderDefinition.OAuthGroupMappingMode.EXPLICITLY_MAPPED;
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
