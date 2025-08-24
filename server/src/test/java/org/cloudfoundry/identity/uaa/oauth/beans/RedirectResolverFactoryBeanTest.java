package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.DefaultRedirectResolver;
import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.RedirectResolver;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class RedirectResolverFactoryBeanTest {

    @Test
    void allowUnsafeMatching_shouldReturnLegacyRedirectResolver() throws Exception {
        FactoryBean<RedirectResolver> factory = new RedirectResolverFactoryBean(true);

        assertThat(factory.getObject()).isInstanceOf(LegacyRedirectResolver.class);
    }

    @Test
    void disallowUnsafeMatching_shouldReturnSpringSecurityOauth2RedirectResolver_withDontMatchSubdomain() throws Exception {
        FactoryBean<RedirectResolver> factory = new RedirectResolverFactoryBean(false);

        RedirectResolver redirectResolver = factory.getObject();
        assertThat(redirectResolver).isInstanceOf(DefaultRedirectResolver.class);
        assertThat(ReflectionTestUtils.getField(redirectResolver, "matchSubdomains")).isEqualTo(false);
    }

}