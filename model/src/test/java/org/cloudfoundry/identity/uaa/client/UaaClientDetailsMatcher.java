package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.ProxyingBeanInfoMatcher;
import org.hamcrest.Matcher;

/**
 * Matcher for UaaClientDetails, Test framework
 */
public interface UaaClientDetailsMatcher extends Matcher<UaaClientDetails> {
    static UaaClientDetailsMatcher aUaaClientDetails() {
        return ProxyingBeanInfoMatcher.proxying(UaaClientDetailsMatcher.class);
    }

    UaaClientDetailsMatcher withClientId(String expected);

    UaaClientDetailsMatcher withClientSecret(String expected);

    UaaClientDetailsMatcher withScope(Matcher<Iterable<?>> expected);

    UaaClientDetailsMatcher withResourceIds(Matcher<Iterable<?>> expected);

    UaaClientDetailsMatcher withAdditionalInformation(Matcher<?> expected);
}