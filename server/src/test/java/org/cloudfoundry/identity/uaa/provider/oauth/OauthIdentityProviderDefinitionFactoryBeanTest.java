package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.STORE_CUSTOM_ATTRIBUTES_NAME;
import static org.junit.Assert.assertFalse;
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
        idpDefinitionMap.put("clientAuthInBody", false);
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

}