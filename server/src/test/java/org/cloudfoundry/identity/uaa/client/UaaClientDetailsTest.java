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

class UaaClientDetailsTest {

  @Nested
    class Creation {
        private UaaClientDetails testClient;

        @BeforeEach
        void setUp() {
            testClient = new UaaClientDetails(
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

        @Test
        void testClientJwtConfig() {
          UaaClientDetails copy = new UaaClientDetails(testClient);
          copy.setClientJwtConfig("test");
          assertEquals("test", copy.getClientJwtConfig());
        }

        @Test
        void testEquals() {
          UaaClientDetails copy = new UaaClientDetails(testClient);
          UaaClientDetails copy2 = new UaaClientDetails(testClient);
          copy.setClientJwtConfig("test");
          assertNotEquals(copy, copy2);
          assertNotEquals(copy, new UaaClientDetails());
          copy.setClientJwtConfig(null);
          assertEquals(copy, copy2);
          assertEquals(copy, copy);
          assertNotEquals(copy, new UaaClientDetails());
        }

        @Test
        void testHashCode() {
          UaaClientDetails copy = new UaaClientDetails(testClient);
          UaaClientDetails copy2 = new UaaClientDetails(testClient.getClientId(), "",
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
            UaaClientDetails client = new UaaClientDetails(new UaaClientDetails());
            client.setScope(Collections.singleton("foo,bar"));
            assertThat(client, is(
                    aUaaClientDetails().withScope(containsInAnyOrder("foo", "bar"))
            ));
        }
    }
}