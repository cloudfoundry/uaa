/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.STORE_CUSTOM_ATTRIBUTES_NAME;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class OauthIdentityProviderDefinitionFactoryBeanTest {

    private OauthIDPWrapperFactoryBean factoryBean;
    private HashMap<String, Object> idpDefinitionMap;
    private OIDCIdentityProviderDefinition providerDefinition;

    @Before
    public void setup() {
        factoryBean = new OauthIDPWrapperFactoryBean(null);
        providerDefinition = new OIDCIdentityProviderDefinition();
        idpDefinitionMap = new HashMap<>();
        idpDefinitionMap.put("authUrl", "http://auth.url");
        idpDefinitionMap.put("relyingPartyId", "theClientId");
        idpDefinitionMap.put("relyingPartySecret", "theClientSecret");
        idpDefinitionMap.put("tokenKey", "key");
        idpDefinitionMap.put("tokenUrl", "http://token.url");
        idpDefinitionMap.put("tokenKeyUrl", "http://token-key.url");
        idpDefinitionMap.put("logoutUrl", "http://logout.url");
        idpDefinitionMap.put("clientAuthInBody", false);
        idpDefinitionMap.put("cacheJwks", true);
    }

    @Test
    public void as_configured() {
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertFalse(providerDefinition.isClientAuthInBody());
    }

    @Test
    public void client_auth_in_body() {
        idpDefinitionMap.put("clientAuthInBody", true);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertTrue(providerDefinition.isClientAuthInBody());
    }

    @Test
    public void store_custom_attributes_default() {
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertTrue(providerDefinition.isStoreCustomAttributes());
    }

    @Test
    public void store_custom_attributes_set_to_true() {
        idpDefinitionMap.put(STORE_CUSTOM_ATTRIBUTES_NAME, true);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertTrue(providerDefinition.isStoreCustomAttributes());
    }

    @Test
    public void store_custom_attributes_set_to_false() {
        idpDefinitionMap.put(STORE_CUSTOM_ATTRIBUTES_NAME, false);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertFalse(providerDefinition.isStoreCustomAttributes());
    }

    @Test
    public void logout_url_in_body() {
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertEquals("http://logout.url", providerDefinition.getLogoutUrl().toString());
    }

    @Test
    public void external_group_mapping_in_body() {
        Map<String, Object> externalGroupMapping = map(
            entry(GROUP_ATTRIBUTE_NAME, "roles")
        );
        idpDefinitionMap.put("groupMappingMode", "AS_SCOPES");
        idpDefinitionMap.put("attributeMappings", externalGroupMapping);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertEquals(externalGroupMapping, providerDefinition.getAttributeMappings());
        assertEquals("AS_SCOPES", providerDefinition.getGroupMappingMode().toString());
    }

    @Test
    public void external_group_mapping_default_in_body() {
        Map<String, Object> externalGroupMapping = map(
            entry(GROUP_ATTRIBUTE_NAME, "roles")
        );
        idpDefinitionMap.put("attributeMappings", externalGroupMapping);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertEquals(externalGroupMapping, providerDefinition.getAttributeMappings());
        assertEquals(null, providerDefinition.getGroupMappingMode());
    }

    @Test
    public void jwtClientAuthenticationTrue() {
        Map<String, Map> definitions = new HashMap<>();
        idpDefinitionMap.put("jwtclientAuthentication", Boolean.valueOf (true));
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertTrue(factoryBean.getProviders().get(0).getProvider().getConfig() instanceof OIDCIdentityProviderDefinition);
        assertNotNull(((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getJwtClientAuthentication());
    }

    @Test
    public void jwtClientAuthenticationNull() {
        Map<String, Map> definitions = new HashMap<>();
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertTrue(factoryBean.getProviders().get(0).getProvider().getConfig() instanceof OIDCIdentityProviderDefinition);
        assertNull(((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getJwtClientAuthentication());
    }

    @Test
    public void jwtClientAuthenticationInvalidType() {
        Map<String, Map> definitions = new HashMap<>();
        idpDefinitionMap.put("jwtclientAuthentication", Integer.valueOf(1));
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertTrue(factoryBean.getProviders().get(0).getProvider().getConfig() instanceof OIDCIdentityProviderDefinition);
        assertNull(((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getJwtClientAuthentication());
    }

    @Test
    public void jwtClientAuthenticationWithCustomSetting() {
        Map<String, Map> definitions = new HashMap<>();
        Map<String, String> settings = new HashMap<>();
        settings.put("iss", "issuer");
        idpDefinitionMap.put("jwtclientAuthentication", settings);
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertTrue(factoryBean.getProviders().get(0).getProvider().getConfig() instanceof OIDCIdentityProviderDefinition);
        assertNotNull(((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getJwtClientAuthentication());
        assertEquals("issuer", (((Map<String, String>)((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getJwtClientAuthentication()).get("iss")));
    }

    @Test
    public void jwtClientAuthenticationWith2EntriesButNewOneMustWin() {
        // given: 2 similar entry because of issue #2752
        idpDefinitionMap.put("jwtclientAuthentication", Map.of("iss", "issuer"));
        idpDefinitionMap.put("jwtClientAuthentication", Map.of("iss", "trueIssuer"));
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        Map<String, Map> definitions = new HashMap<>();
        definitions.put("test", idpDefinitionMap);
        // when: load beans from uaa.yml
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        // then
        assertTrue(factoryBean.getProviders().get(0).getProvider().getConfig() instanceof OIDCIdentityProviderDefinition);
        assertNotNull(((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getJwtClientAuthentication());
        assertNotEquals("issuer", (((Map<String, String>)((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getJwtClientAuthentication()).get("iss")));
        assertEquals("trueIssuer", (((Map<String, String>)((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getJwtClientAuthentication()).get("iss")));
    }

    @Test
    public void testNoDiscoveryUrl() {
        Map<String, Map> definitions = new HashMap<>();
        idpDefinitionMap.remove("discoveryUrl");
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertTrue(factoryBean.getProviders().get(0).getProvider().getConfig() instanceof OIDCIdentityProviderDefinition);
        assertNull(((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getDiscoveryUrl());
        assertEquals("http://auth.url", ((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getAuthUrl().toString());
        assertEquals("http://token-key.url", ((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getTokenKeyUrl().toString());
        assertEquals("http://token.url", ((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getTokenUrl().toString());
        assertEquals("http://logout.url", ((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getLogoutUrl().toString());
    }

    @Test
    public void testDiscoveryUrl() {
        Map<String, Map> definitions = new HashMap<>();
        idpDefinitionMap.put("discoveryUrl", "http://localhost:8080/uaa/.well-known/openid-configuration");
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertTrue(factoryBean.getProviders().get(0).getProvider().getConfig() instanceof OIDCIdentityProviderDefinition);
        assertEquals("http://localhost:8080/uaa/.well-known/openid-configuration", ((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getDiscoveryUrl().toString());
        assertNull(((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getAuthUrl());
        assertNull(((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getTokenKeyUrl());
        assertNull(((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getTokenUrl());
        assertNull(((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getLogoutUrl());
    }

    @Test
    public void testAdditionalParametersInConfig() {
        Map<String, Object> additionalMap = new HashMap<>();
        Map<String, Map> definitions = new HashMap<>();
        additionalMap.put("token_format", "jwt");
        additionalMap.put("expires", 0);
        additionalMap.put("code", 12345678);
        additionalMap.put("client_id", "id");
        additionalMap.put("complex", Set.of("1", "2"));
        additionalMap.put("null", null);
        additionalMap.put("empty", "");
        idpDefinitionMap.put("additionalAuthzParameters", additionalMap);
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertTrue(factoryBean.getProviders().get(0).getProvider().getConfig() instanceof OIDCIdentityProviderDefinition);
        Map<String, String> receivedParameters = ((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getAdditionalAuthzParameters();
        assertEquals(3, receivedParameters.size());
        assertEquals("jwt", receivedParameters.get("token_format"));
        assertEquals("0", receivedParameters.get("expires"));
        assertEquals("", receivedParameters.get("empty"));
    }

    @Test
    public void testNoAdditionalParametersInConfig() {
        Map<String, Map> definitions = new HashMap<>();
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertTrue(factoryBean.getProviders().get(0).getProvider().getConfig() instanceof OIDCIdentityProviderDefinition);
        Map<String, String> receivedParameters = ((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getAdditionalAuthzParameters();
        assertEquals(0, receivedParameters.size());
    }

    @Test
    public void testPerformRpInitiatedLogoutTrue() {
        idpDefinitionMap.put("performRpInitiatedLogout", true);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertTrue(providerDefinition.isPerformRpInitiatedLogout());
    }

    @Test
    public void testPerformRpInitiatedLogoutFalse() {
        idpDefinitionMap.put("performRpInitiatedLogout", false);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertFalse(providerDefinition.isPerformRpInitiatedLogout());
    }

    @Test
    public void testAuthMethodNotSet() {
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertNull(providerDefinition.getAuthMethod());
        assertEquals(ClientAuthentication.CLIENT_SECRET_BASIC, ClientAuthentication.getCalculatedMethod(providerDefinition.getAuthMethod(), providerDefinition.getRelyingPartySecret() != null, providerDefinition.getJwtClientAuthentication() != null));
    }

    @Test
    public void testAuthMethodSetInvalidValue() {
        idpDefinitionMap.put("authMethod", "empty");
        assertThrows(IllegalArgumentException.class, () -> factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition));
    }

    @Test
    public void testAuthMethodSet() {
        // given: jwtclientAuthentication, but overrule it with authMethod=none
        idpDefinitionMap.put("jwtclientAuthentication", true);
        idpDefinitionMap.put("authMethod", "none");
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        Map<String, Map> definitions = new HashMap<>();
        definitions.put("new.idp", idpDefinitionMap);
        // when: load beans from uaa.yml
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        // then
        assertTrue(factoryBean.getProviders().get(0).getProvider().getConfig() instanceof OIDCIdentityProviderDefinition);
        assertNotNull(((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getJwtClientAuthentication());
        assertEquals("none", (((OIDCIdentityProviderDefinition) factoryBean.getProviders().get(0).getProvider().getConfig()).getAuthMethod()));
    }
}
