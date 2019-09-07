package org.cloudfoundry.identity.uaa.oauth.beans;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;
import org.springframework.security.oauth2.provider.endpoint.RedirectResolver;
import org.springframework.test.util.ReflectionTestUtils;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.is;

class RedirectResolverFactoryBeanTest {

    @Test
    void allowUnsafeMatching_shouldReturnLegacyRedirectResolver() throws Exception {
        FactoryBean<RedirectResolver> factory = new RedirectResolverFactoryBean(true);

        assertThat(factory.getObject(), instanceOf(LegacyRedirectResolver.class));
    }

    @Test
    void disallowUnsafeMatching_shouldReturnSpringSecurityOauth2RedirectResolver_withDontMatchSubdomain() throws Exception {
        FactoryBean<RedirectResolver> factory = new RedirectResolverFactoryBean(false);

        RedirectResolver redirectResolver = factory.getObject();
        assertThat(redirectResolver, instanceOf(DefaultRedirectResolver.class));
        assertThat(ReflectionTestUtils.getField(redirectResolver, "matchSubdomains"), is(false));
    }

}