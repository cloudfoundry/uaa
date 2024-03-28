package org.cloudfoundry.identity.uaa.client;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class UaaBaseClientDetailsTest {

  @Nested
    class Creation {
        private UaaBaseClientDetails testClient;

        @BeforeEach
        void setUp() {
            testClient = new UaaBaseClientDetails(
                    "test",
                    "",
                    "test.none",
                    "",
                    "test.admin"
            );
        }

        @Test
        void copiesUaaBaseClientDetails() {
            testClient.setClientSecret("secret");
            UaaBaseClientDetails copy = new UaaBaseClientDetails(testClient);
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
            UaaBaseClientDetails copy = new UaaBaseClientDetails(testClient);
            assertThat(copy, is(
                    aUaaClientDetails()
                            .withAdditionalInformation(allOf(aMapWithSize(1), hasEntry("key", "value")))
            ));
        }

        @Test
        void testClientJwtConfig() {
          UaaBaseClientDetails copy = new UaaBaseClientDetails(testClient);
          copy.setClientJwtConfig("test");
          assertEquals("test", copy.getClientJwtConfig());
        }

        @Test
        void testEquals() {
          UaaBaseClientDetails copy = new UaaBaseClientDetails(testClient);
          UaaBaseClientDetails copy2 = new UaaBaseClientDetails(testClient);
          copy.setClientJwtConfig("test");
          assertNotEquals(copy, copy2);
          assertNotEquals(copy, new UaaBaseClientDetails());
          copy.setClientJwtConfig(null);
          assertEquals(copy, copy2);
          assertEquals(copy, copy);
          assertNotEquals(copy, new UaaBaseClientDetails());
        }

        @Test
        void testHashCode() {
          UaaBaseClientDetails copy = new UaaBaseClientDetails(testClient);
          UaaBaseClientDetails copy2 = new UaaBaseClientDetails(testClient.getClientId(), "",
              "test.none", "", "test.admin", null);
          assertEquals(copy.hashCode(), copy2.hashCode());
          copy.setClientJwtConfig("test");
          assertNotEquals(copy.hashCode(), copy2.hashCode());
        }
    }

    @Nested
    class WhenSettingScope {
        @Test
        void splitsScopesWhichIncludeAComma() {
            UaaBaseClientDetails client = new UaaBaseClientDetails(new UaaBaseClientDetails());
            client.setScope(Collections.singleton("foo,bar"));
            assertThat(client, is(
                    aUaaClientDetails().withScope(containsInAnyOrder("foo", "bar"))
            ));
        }
    }
}