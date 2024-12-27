package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.client.DefaultOAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class OAuth2ClientContextFactoryBeanTest {

    private OAuth2ClientContextFactoryBean factoryBean;

    @Before
    public void setUp() throws Exception {
        factoryBean = new OAuth2ClientContextFactoryBean();
    }

    @Test
    public void getObject() throws Exception {
        OAuth2ClientContext scopedContext = new DefaultOAuth2ClientContext();
        OAuth2ClientContext bareContext = new DefaultOAuth2ClientContext();
        factoryBean.setBareContext(bareContext);
        factoryBean.setScopedContext(scopedContext);
        assertEquals(scopedContext, factoryBean.getObject());
        factoryBean.setResource(new ClientCredentialsResourceDetails());
        assertEquals(bareContext, factoryBean.getObject());
    }

    @Test
    public void getObjectType() {
        assertEquals(OAuth2ClientContext.class, factoryBean.getObjectType());
    }

    @Test
    public void isSingleton() {
        assertTrue(factoryBean.isSingleton());
    }
}
