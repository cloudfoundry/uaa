package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.ProxyingBeanInfoMatcher;
import org.hamcrest.Matcher;

public interface UaaClientDetailsMatcher extends Matcher<UaaBaseClientDetails> {
    static UaaClientDetailsMatcher aUaaClientDetails() {
        return ProxyingBeanInfoMatcher.proxying(UaaClientDetailsMatcher.class);
    }

    UaaClientDetailsMatcher withClientId(String expected);
    UaaClientDetailsMatcher withClientSecret(String expected);
    UaaClientDetailsMatcher withScope(Matcher<Iterable<?>> expected);
    UaaClientDetailsMatcher withResourceIds(Matcher<Iterable<?>> expected);
    UaaClientDetailsMatcher withAdditionalInformation(Matcher<?> expected);
}