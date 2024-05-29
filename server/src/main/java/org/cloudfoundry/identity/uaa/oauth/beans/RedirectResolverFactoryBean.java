package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.RedirectResolver;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.stereotype.Component;

@Component
public class RedirectResolverFactoryBean implements FactoryBean<RedirectResolver> {

    private final boolean allowUnsafeMatching;

    public RedirectResolverFactoryBean(
            @Value("${uaa.oauth.redirect_uri.allow_unsafe_matching:true}") boolean allowUnsafeMatching
    ) {
        this.allowUnsafeMatching = allowUnsafeMatching;
    }

    @Override
    public RedirectResolver getObject() {
        NormalizedRedirectResolver defaultRedirectResolver = new NormalizedRedirectResolver();
        defaultRedirectResolver.setMatchSubdomains(false);
        return allowUnsafeMatching ? new LegacyRedirectResolver() : defaultRedirectResolver;
    }

    @Override
    public Class<?> getObjectType() {
        return RedirectResolver.class;
    }

    @Override
    public boolean isSingleton() {
        return true;
    }
}
