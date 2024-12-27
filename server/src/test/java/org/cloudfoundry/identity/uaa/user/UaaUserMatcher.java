package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.ProxyingBeanInfoMatcher;
import org.hamcrest.Matcher;

import java.util.Date;

public interface UaaUserMatcher extends Matcher<UaaUser> {
    static UaaUserMatcher aUaaUser() {
        return ProxyingBeanInfoMatcher.proxying(UaaUserMatcher.class);
    }

    UaaUserMatcher withId(String expected);

    UaaUserMatcher withUsername(String expected);

    UaaUserMatcher withPassword(String expected);

    UaaUserMatcher withEmail(String expected);

    UaaUserMatcher withPhoneNumber(String expected);

    UaaUserMatcher withGivenName(String expected);

    UaaUserMatcher withFamilyName(String expected);

    UaaUserMatcher withOrigin(String expected);

    UaaUserMatcher withExternalId(String expected);

    UaaUserMatcher withZoneId(String expected);

    UaaUserMatcher withAuthorities(Matcher<Iterable<?>> expected);

    UaaUserMatcher withVerified(Boolean expected);

    UaaUserMatcher withCreated(Matcher<Date> expected);

    UaaUserMatcher withModified(Matcher<Date> expected);
}
