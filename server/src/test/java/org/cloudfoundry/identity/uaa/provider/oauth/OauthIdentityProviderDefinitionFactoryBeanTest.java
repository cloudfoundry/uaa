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
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.STORE_CUSTOM_ATTRIBUTES_NAME;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.entry;
import static org.cloudfoundry.identity.uaa.util.UaaMapUtils.map;

class OauthIdentityProviderDefinitionFactoryBeanTest {

    private OauthIDPWrapperFactoryBean factoryBean;
    private HashMap<String, Object> idpDefinitionMap;
    private OIDCIdentityProviderDefinition providerDefinition;

    @BeforeEach
    void setup() {
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
    void as_configured() {
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(providerDefinition.isClientAuthInBody()).isFalse();
    }

    @Test
    void client_auth_in_body() {
        idpDefinitionMap.put("clientAuthInBody", true);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(providerDefinition.isClientAuthInBody()).isTrue();
    }

    @Test
    void store_custom_attributes_default() {
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(providerDefinition.isStoreCustomAttributes()).isTrue();
    }

    @Test
    void store_custom_attributes_set_to_true() {
        idpDefinitionMap.put(STORE_CUSTOM_ATTRIBUTES_NAME, true);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(providerDefinition.isStoreCustomAttributes()).isTrue();
    }

    @Test
    void store_custom_attributes_set_to_false() {
        idpDefinitionMap.put(STORE_CUSTOM_ATTRIBUTES_NAME, false);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(providerDefinition.isStoreCustomAttributes()).isFalse();
    }

    @Test
    void logout_url_in_body() {
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(providerDefinition.getLogoutUrl()).hasToString("http://logout.url");
    }

    @Test
    void external_group_mapping_in_body() {
        Map<String, Object> externalGroupMapping = map(
                entry(GROUP_ATTRIBUTE_NAME, "roles")
        );
        idpDefinitionMap.put("groupMappingMode", "AS_SCOPES");
        idpDefinitionMap.put("attributeMappings", externalGroupMapping);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(providerDefinition.getAttributeMappings()).isEqualTo(externalGroupMapping);
        assertThat(providerDefinition.getGroupMappingMode()).hasToString("AS_SCOPES");
    }

    @Test
    void external_group_mapping_default_in_body() {
        Map<String, Object> externalGroupMapping = map(
                entry(GROUP_ATTRIBUTE_NAME, "roles")
        );
        idpDefinitionMap.put("attributeMappings", externalGroupMapping);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(providerDefinition.getAttributeMappings()).isEqualTo(externalGroupMapping);
        assertThat(providerDefinition.getGroupMappingMode()).isNull();
    }

    @Test
    void jwtClientAuthenticationTrue() {
        Map<String, Map> definitions = new HashMap<>();
        idpDefinitionMap.put("jwtclientAuthentication", Boolean.TRUE);
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(factoryBean.getProviders().getFirst().getProvider().getConfig()).isInstanceOf(OIDCIdentityProviderDefinition.class);
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getJwtClientAuthentication()).isNotNull();
    }

    @Test
    void jwtClientAuthenticationNull() {
        Map<String, Map> definitions = new HashMap<>();
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(factoryBean.getProviders().getFirst().getProvider().getConfig()).isInstanceOf(OIDCIdentityProviderDefinition.class);
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getJwtClientAuthentication()).isNull();
    }

    @Test
    void jwtClientAuthenticationInvalidType() {
        Map<String, Map> definitions = new HashMap<>();
        idpDefinitionMap.put("jwtclientAuthentication", 1);
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(factoryBean.getProviders().getFirst().getProvider().getConfig()).isInstanceOf(OIDCIdentityProviderDefinition.class);
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getJwtClientAuthentication()).isNull();
    }

    @Test
    void jwtClientAuthenticationWithCustomSetting() {
        Map<String, Map> definitions = new HashMap<>();
        Map<String, String> settings = new HashMap<>();
        settings.put("iss", "issuer");
        idpDefinitionMap.put("jwtclientAuthentication", settings);
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(factoryBean.getProviders().getFirst().getProvider().getConfig()).isInstanceOf(OIDCIdentityProviderDefinition.class);
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getJwtClientAuthentication()).isNotNull();
        assertThat((Map<String, String>) ((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getJwtClientAuthentication())
                .containsEntry("iss", "issuer");
    }

    @Test
    void jwtClientAuthenticationWith2EntriesButNewOneMustWin() {
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
        assertThat(factoryBean.getProviders().getFirst().getProvider().getConfig()).isInstanceOf(OIDCIdentityProviderDefinition.class);
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getJwtClientAuthentication()).isNotNull();
        assertThat((((Map<String, String>) ((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getJwtClientAuthentication()).get("iss")))
                .isNotEqualTo("issuer")
                .isEqualTo("trueIssuer");
    }

    @Test
    void noDiscoveryUrl() {
        Map<String, Map> definitions = new HashMap<>();
        idpDefinitionMap.remove("discoveryUrl");
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(factoryBean.getProviders().getFirst().getProvider().getConfig()).isInstanceOf(OIDCIdentityProviderDefinition.class);
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getDiscoveryUrl()).isNull();
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getAuthUrl()).hasToString("http://auth.url");
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getTokenKeyUrl()).hasToString("http://token-key.url");
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getTokenUrl()).hasToString("http://token.url");
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getLogoutUrl()).hasToString("http://logout.url");
    }

    @Test
    void discoveryUrl() {
        Map<String, Map> definitions = new HashMap<>();
        idpDefinitionMap.put("discoveryUrl", "http://localhost:8080/uaa/.well-known/openid-configuration");
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(factoryBean.getProviders().getFirst().getProvider().getConfig()).isInstanceOf(OIDCIdentityProviderDefinition.class);
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getDiscoveryUrl()).hasToString("http://localhost:8080/uaa/.well-known/openid-configuration");
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getAuthUrl()).isNull();
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getTokenKeyUrl()).isNull();
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getTokenUrl()).isNull();
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getLogoutUrl()).isNull();
    }

    @Test
    void additionalParametersInConfig() {
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
        assertThat(factoryBean.getProviders().getFirst().getProvider().getConfig()).isInstanceOf(OIDCIdentityProviderDefinition.class);
        Map<String, String> receivedParameters = ((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getAdditionalAuthzParameters();
        assertThat(receivedParameters).hasSize(3)
                .containsEntry("token_format", "jwt")
                .containsEntry("expires", "0");
        assertThat(receivedParameters.get("empty")).isEmpty();
    }

    @Test
    void noAdditionalParametersInConfig() {
        Map<String, Map> definitions = new HashMap<>();
        idpDefinitionMap.put("type", OriginKeys.OIDC10);
        definitions.put("test", idpDefinitionMap);
        factoryBean = new OauthIDPWrapperFactoryBean(definitions);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(factoryBean.getProviders().getFirst().getProvider().getConfig()).isInstanceOf(OIDCIdentityProviderDefinition.class);
        Map<String, String> receivedParameters = ((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getAdditionalAuthzParameters();
        assertThat(receivedParameters).isEmpty();
    }

    @Test
    void performRpInitiatedLogoutTrue() {
        idpDefinitionMap.put("performRpInitiatedLogout", true);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(providerDefinition.isPerformRpInitiatedLogout()).isTrue();
    }

    @Test
    void performRpInitiatedLogoutFalse() {
        idpDefinitionMap.put("performRpInitiatedLogout", false);
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(providerDefinition.isPerformRpInitiatedLogout()).isFalse();
    }

    @Test
    void authMethodNotSet() {
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);
        assertThat(providerDefinition.getAuthMethod()).isNull();
        assertThat(ClientAuthentication.getCalculatedMethod(providerDefinition.getAuthMethod(), providerDefinition.getRelyingPartySecret() != null, providerDefinition.getJwtClientAuthentication() != null)).isEqualTo(ClientAuthentication.CLIENT_SECRET_BASIC);
    }

    @Test
    void authMethodSetInvalidValue() {
        idpDefinitionMap.put("authMethod", "empty");
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition));
    }

    @Test
    void authMethodSet() {
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
        assertThat(factoryBean.getProviders().getFirst().getProvider().getConfig()).isInstanceOf(OIDCIdentityProviderDefinition.class);
        assertThat(((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getJwtClientAuthentication()).isNotNull();
        assertThat((((OIDCIdentityProviderDefinition) factoryBean.getProviders().getFirst().getProvider().getConfig()).getAuthMethod())).isEqualTo("none");
    }

    /* The following two test cases check whether different values for 'setForwardHeader' and 'passwordGrantEnabled' are
     * allowed. Due to a copy/paste issue, the value of 'setForwardHeader' was previously always set to the same value
     * as 'passwordGrantEnabled'. */
    @Test
    void setForwardHeaderShouldAllowValuesDifferentFromPasswordGrantEnabledTrue() {
        testSetForwardHeader_ShouldAllowValuesDifferentFromPasswordGrantEnabled(true);
    }

    @Test
    void setForwardHeaderShouldAllowValuesDifferentFromPasswordGrantEnabledFalse() {
        testSetForwardHeader_ShouldAllowValuesDifferentFromPasswordGrantEnabled(false);
    }

    private void testSetForwardHeader_ShouldAllowValuesDifferentFromPasswordGrantEnabled(
            final boolean setForwardHeader
    ) {
        idpDefinitionMap.put("setForwardHeader", setForwardHeader);
        idpDefinitionMap.put("passwordGrantEnabled", !setForwardHeader);
        idpDefinitionMap.put("type", OriginKeys.OIDC10);

        factoryBean = new OauthIDPWrapperFactoryBean(Collections.singletonMap("new.idp", idpDefinitionMap));
        factoryBean.setCommonProperties(idpDefinitionMap, providerDefinition);

        final IdentityProvider provider = factoryBean.getProviders().getFirst().getProvider();
        assertThat(provider.getConfig()).isInstanceOf(OIDCIdentityProviderDefinition.class);
        final OIDCIdentityProviderDefinition providerConfig = (OIDCIdentityProviderDefinition) provider.getConfig();
        assertThat(providerConfig.isSetForwardHeader()).isEqualTo(setForwardHeader);
        assertThat(providerConfig.isPasswordGrantEnabled()).isNotEqualTo(setForwardHeader);
    }
}
