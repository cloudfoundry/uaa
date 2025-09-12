package org.cloudfoundry.identity.uaa.user;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.cloudfoundry.identity.uaa.user.UaaUserMatcher.aUaaUser;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;

class UaaUserTests {
    @Nested
    class EmailFrom {
        @Nested
        class WhenInputDoesNotContainAtSymbol {
            @Test
            void constructsEmailFromInputAndDefaultDomain() {
                final String name = "user";
                assertEquals(name + "@" + UaaUser.DEFAULT_EMAIL_DOMAIN, UaaUser.emailFrom(name));
            }
        }

        @Nested
        class WhenInputContainsLeadingAtSymbol {
            @Test
            void constructsEmailFromInputAndDefaultDomain() {
                final String name = "user";
                assertEquals(name + "@" + UaaUser.DEFAULT_EMAIL_DOMAIN, UaaUser.emailFrom("@" + name));
            }
        }

        @Nested
        class WhenInputContainsTrailingAtSymbol {
            @Test
            void constructsEmailFromInputAndDefaultDomain() {
                final String name = "user";
                assertEquals(name + "@" + UaaUser.DEFAULT_EMAIL_DOMAIN, UaaUser.emailFrom(name + "@"));
            }
        }

        @Nested
        class WhenInputLooksLikeAnEmailAddress {
            @Test
            void returnsTheInput() {
                final String name = "user@example.com";
                assertEquals(name, UaaUser.emailFrom(name));
            }
        }
    }

    @Nested
    class FromIncompletePrototype {
        @Nested
        class WhenMissingUsername {
            @Test
            void defaultsUsernameToEmail() {
                UaaUser user = UaaUser.createWithDefaults(u -> u.withEmail("user@example.com"));
                assertThat(user, is(aUaaUser().withUsername("user@example.com")));
            }

            @Test
            void defaultsUsernameToUnknownWhenNoEmailPresent() {
                UaaUser user = UaaUser.createWithDefaults(u -> {});
                assertThat(user, is(aUaaUser().withUsername(UaaUser.DEFAULT_USER_NAME)));
            }
        }

        @Nested
        class WhenMissingEmail {
            @Test
            void defaultsEmailFromUsername() {
                UaaUser user = UaaUser.createWithDefaults(u -> u.withUsername("name"));
                assertThat(user, is(aUaaUser().withEmail("name" + "@" + UaaUser.DEFAULT_EMAIL_DOMAIN)));
            }
        }

        @Nested
        class WhenMissingGivenName {
            @Test
            void defaultsGivenNameAsNull() {
                UaaUser user = UaaUser.createWithDefaults(u -> u.withUsername("user").withEmail("name@example.com"));
                assertThat(user, is(aUaaUser().withGivenName(null)));
            }
        }

        @Nested
        class WhenMissingFamilyName {
            @Test
            void defaultsFamilyNameAsNull() {
                UaaUser user = UaaUser.createWithDefaults(u -> u.withUsername("user").withEmail("name@example.com"));
                assertThat(user, is(aUaaUser().withFamilyName(null)));
            }
        }

        @Nested
        class WhenMissingCreated {
            @Test
            void defaultsToNow() {
                Date now = new Date();

                UaaUser user = UaaUser.createWithDefaults(u -> u.withUsername("user"));
                assertThat(user, is(aUaaUser().withCreated(greaterThanOrEqualTo(now))));
            }
        }

        @Nested
        class WhenMissingModified {
            @Test
            void defaultsToNow() {
                Date now = new Date();

                UaaUser user = UaaUser.createWithDefaults(u -> u.withUsername("user"));
                assertThat(user, is(aUaaUser().withModified(greaterThanOrEqualTo(user.getCreated()))));
                assertThat(user, is(aUaaUser().withModified(greaterThanOrEqualTo(now))));
            }
        }
    }
}
