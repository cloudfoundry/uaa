package org.cloudfoundry.identity.uaa.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.client.UaaClientDetailsMatcher.aUaaClientDetails;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.emptyIterable;
import static org.hamcrest.collection.IsIterableContainingInOrder.contains;
import static org.hamcrest.collection.IsMapContaining.hasEntry;
import static org.hamcrest.collection.IsMapWithSize.aMapWithSize;

class UaaClientDetailsTest {
    @Nested
    static class Creation {
        private BaseClientDetails testClient;

        @BeforeEach
        void setUp() {
            testClient = new BaseClientDetails(
                    "test",
                    "",
                    "test.none",
                    "",
                    "test.admin"
            );
        }

        @Test
        void copiesBaseClientDetails() {
            testClient.setClientSecret("secret");
            UaaClientDetails copy = new UaaClientDetails(testClient);
            assertThat(copy, is(
                    aUaaClientDetails()
                            .withClientId("test")
                            .withClientSecret("secret")
                            .withScope(contains("test.none"))
                            .withResourceIds(emptyIterable())
            ));

            List<String> authorities = copy.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            assertThat(authorities, contains("test.admin"));
        }

        @Test
        void copiesAdditionalInformation() {
            testClient.setAdditionalInformation(Collections.singletonMap("key", "value"));
            UaaClientDetails copy = new UaaClientDetails(testClient);
            assertThat(copy, is(
                    aUaaClientDetails()
                            .withAdditionalInformation(allOf(aMapWithSize(1), hasEntry("key", "value")))
            ));
        }
    }

    @Nested
    static class WhenSettingScope {
        @Test
        void splitsScopesWhichIncludeAComma() {
            UaaClientDetails client = new UaaClientDetails(new BaseClientDetails());
            client.setScope(Collections.singleton("foo,bar"));
            assertThat(client, is(
                    aUaaClientDetails().withScope(containsInAnyOrder("foo", "bar"))
            ));
        }
    }
}