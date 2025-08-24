package org.cloudfoundry.identity.uaa.oauth.provider.config.xml;

import org.cloudfoundry.identity.uaa.oauth.client.DefaultOAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.OAuth2ClientContext;
import org.cloudfoundry.identity.uaa.oauth.client.resource.ClientCredentialsResourceDetails;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
class OAuth2ClientContextFactoryBeanTest {

    private OAuth2ClientContextFactoryBean factoryBean;

    @BeforeEach
    void setUp() throws Exception {
        factoryBean = new OAuth2ClientContextFactoryBean();
    }

    @Test
    void getObject() throws Exception {
        OAuth2ClientContext scopedContext = new DefaultOAuth2ClientContext();
        OAuth2ClientContext bareContext = new DefaultOAuth2ClientContext();
        factoryBean.setBareContext(bareContext);
        factoryBean.setScopedContext(scopedContext);
        assertThat(factoryBean.getObject()).isEqualTo(scopedContext);
        factoryBean.setResource(new ClientCredentialsResourceDetails());
        assertThat(factoryBean.getObject()).isEqualTo(bareContext);
    }

    @Test
    void getObjectType() {
        assertThat(factoryBean.getObjectType()).isEqualTo(OAuth2ClientContext.class);
    }

    @Test
    void isSingleton() {
        assertThat(factoryBean.isSingleton()).isTrue();
    }
}
