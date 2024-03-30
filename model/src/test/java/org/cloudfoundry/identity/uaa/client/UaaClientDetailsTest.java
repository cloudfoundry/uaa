package org.cloudfoundry.identity.uaa.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.hamcrest.collection.IsIterableContainingInOrder;
import org.hamcrest.collection.IsMapContaining;
import org.hamcrest.collection.IsMapWithSize;
import org.junit.Assert;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
            MatcherAssert.assertThat(copy, CoreMatchers.is(
                    UaaClientDetailsMatcher.aUaaClientDetails()
                            .withClientId("test")
                            .withClientSecret("secret")
                            .withScope(IsIterableContainingInOrder.contains("test.none"))
                            .withResourceIds(Matchers.emptyIterable())
            ));

            List<String> authorities = copy.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());
            MatcherAssert.assertThat(authorities, IsIterableContainingInOrder.contains("test.admin"));
        }

        @Test
        void copiesAdditionalInformation() {
            testClient.setAdditionalInformation(Collections.singletonMap("key", "value"));
            UaaClientDetails copy = new UaaClientDetails(testClient);
            MatcherAssert.assertThat(copy, CoreMatchers.is(
                    UaaClientDetailsMatcher.aUaaClientDetails()
                            .withAdditionalInformation(Matchers.allOf(IsMapWithSize.aMapWithSize(1), IsMapContaining.hasEntry("key", "value")))
            ));
        }

        @Test
        void testClientJwtConfig() {
          UaaClientDetails copy = new UaaClientDetails(testClient);
          copy.setClientJwtConfig("test");
          Assertions.assertEquals("test", copy.getClientJwtConfig());
        }

        @Test
        void testEquals() {
          UaaClientDetails copy = new UaaClientDetails(testClient);
          UaaClientDetails copy2 = new UaaClientDetails(testClient);
          copy.setClientJwtConfig("test");
          assertNotEquals(copy, copy2);
          assertNotEquals(copy, new UaaClientDetails());
          copy.setClientJwtConfig(null);
          Assertions.assertEquals(copy, copy2);
          Assertions.assertEquals(copy, copy);
          assertNotEquals(copy, new UaaClientDetails());
        }

        @Test
        void testHashCode() {
          UaaClientDetails copy = new UaaClientDetails(testClient);
          UaaClientDetails copy2 = new UaaClientDetails(testClient.getClientId(), "",
              "test.none", "", "test.admin", null);
          Assertions.assertEquals(copy.hashCode(), copy2.hashCode());
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
            MatcherAssert.assertThat(client, CoreMatchers.is(
                    UaaClientDetailsMatcher.aUaaClientDetails().withScope(Matchers.containsInAnyOrder("foo", "bar"))
            ));
        }
    }

  @Nested
  class BaseClientDetails {
    @Test
    void testBaseClientDetailsDefaultConstructor() {
      UaaClientDetails details = new UaaClientDetails();
      Assert.assertEquals("[]", details.getResourceIds().toString());
      Assert.assertEquals("[]", details.getScope().toString());
      Assert.assertEquals("[]", details.getAuthorizedGrantTypes().toString());
      Assert.assertEquals("[]", details.getAuthorities().toString());
    }

    @Test
    void testBaseClientDetailsConvenienceConstructor() {
      UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
      Assert.assertEquals("[]", details.getResourceIds().toString());
      Assert.assertEquals("[bar, foo]", new TreeSet<String>(details.getScope()).toString());
      Assert.assertEquals("[authorization_code]", details.getAuthorizedGrantTypes().toString());
      Assert.assertEquals("[ROLE_USER]", details.getAuthorities().toString());
    }

    @Test
    void testBaseClientDetailsAutoApprove() {
      UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
      details.setAutoApproveScopes(StringUtils.commaDelimitedListToSet("read,write"));
      assertTrue(details.isAutoApprove("read"));
    }

    @Test
    void testBaseClientDetailsImplicitAutoApprove() {
      UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
      details.setAutoApproveScopes(StringUtils.commaDelimitedListToSet("true"));
      assertTrue(details.isAutoApprove("read"));
    }

    @Test
    void testBaseClientDetailsNoAutoApprove() {
      UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
      details.setAutoApproveScopes(StringUtils.commaDelimitedListToSet("none"));
      assertFalse(details.isAutoApprove("read"));
    }

    @Test
    void testBaseClientDetailsNullAutoApprove() {
      UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
      assertFalse(details.isAutoApprove("read"));
    }

    @Test
    void testJsonSerialize() throws Exception {
      UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
      details.setClientId("foo");
      details.setClientSecret("bar");
      String value = new ObjectMapper().writeValueAsString(details);
      assertTrue(value.contains("client_id"));
      assertTrue(value.contains("client_secret"));
      assertTrue(value.contains("authorized_grant_types"));
      assertTrue(value.contains("[\"ROLE_USER\"]"));
    }

    @Test
    void testJsonSerializeAdditionalInformation() throws Exception {
      UaaClientDetails details = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
      details.setClientId("foo");
      details.setAdditionalInformation(Collections.singletonMap("foo", "bar"));
      String value = new ObjectMapper().writeValueAsString(details);
      assertTrue(value.contains("\"foo\":\"bar\""));
    }

    @Test
    void testJsonDeserialize() throws Exception {
      String value = "{\"foo\":\"bar\",\"client_id\":\"foo\",\"scope\":[\"bar\",\"foo\"],\"authorized_grant_types\":[\"authorization_code\"],\"authorities\":[\"ROLE_USER\"]}";
      UaaClientDetails details = new ObjectMapper().readValue(value, UaaClientDetails.class);
      UaaClientDetails expected = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER");
      expected.setAdditionalInformation(Collections.singletonMap("foo", (Object)"bar"));
      Assert.assertEquals(expected, details);
    }

    @Test
    void testJsonDeserializeWithArraysAsStrings() throws Exception {
      // Collection values can be deserialized from space or comma-separated lists
      String value = "{\"foo\":\"bar\",\"client_id\":\"foo\",\"scope\":\"bar  foo\",\"authorized_grant_types\":\"authorization_code\",\"authorities\":\"ROLE_USER,ROLE_ADMIN\"}";
      UaaClientDetails details = new ObjectMapper().readValue(value, UaaClientDetails.class);
      UaaClientDetails expected = new UaaClientDetails("foo", "", "foo,bar", "authorization_code", "ROLE_USER,ROLE_ADMIN");
      expected.setAdditionalInformation(Collections.singletonMap("foo", (Object)"bar"));
      Assert.assertEquals(expected, details);
    }

    @Test
    void testEqualityOfValidity() {
      UaaClientDetails details = new UaaClientDetails();
      details.setAccessTokenValiditySeconds(100);
      UaaClientDetails other = new UaaClientDetails();
      other.setAccessTokenValiditySeconds(100);
      Assert.assertEquals(details, other);
    }

    @Test
    void testIsScoped() {
      UaaClientDetails details = new UaaClientDetails();
      assertFalse(details.isScoped());
    }

    @Test
    void testIsSecretRequired() {
      UaaClientDetails details = new UaaClientDetails();
      assertFalse(details.isSecretRequired());
    }

    @Test
    void testAutoApprove() {
      UaaClientDetails details = new UaaClientDetails();
      assertNull(details.getAutoApproveScopes());
    }

    @Test
    void testHashCode() {
      UaaClientDetails uaaClientDetails = new UaaClientDetails("admin", "uaa", "uaa.none",
          "client_credentials", "none", null);
      uaaClientDetails.setRegisteredRedirectUri(Set.of("http://localhost:8080/uaa"));
      uaaClientDetails.setRefreshTokenValiditySeconds(1);
      uaaClientDetails.setAccessTokenValiditySeconds(1);
      assertTrue(uaaClientDetails.hashCode() > 0);
    }
  }

  @Nested
  class Equals {
    private UaaClientDetails testClient;
    private UaaClientDetails testClientCompare;

    @BeforeEach
    void setUp() {
      testClient = new UaaClientDetails("test", null, null, null, null);
      testClientCompare = new UaaClientDetails(testClient);
    }

    @Test
    void testEquals() {
      UaaClientDetails uaaClientDetails = new UaaClientDetails("admin", null, null,
          null, null, null);
      UaaClientDetails uaaClientDetails1 = new UaaClientDetails(uaaClientDetails);
      assertEquals(uaaClientDetails, uaaClientDetails1);
      assertNotEquals(uaaClientDetails, new Object());
      assertNotEquals(null, uaaClientDetails);
    }
    @Test
    void testEqualScope() {
      assertEquals(testClient, testClientCompare);
      testClientCompare.setScope(Set.of("new"));
      assertNotEquals(testClient, testClientCompare);
    }

    @Test
    void testEqualAdditionalInformation() {
      assertEquals(testClient, testClientCompare);
      testClientCompare.setAdditionalInformation(Map.of("n", "v"));
      assertNotEquals(testClient, testClientCompare);
    }

    @Test
    void testEqualResourceIds() {
      assertEquals(testClient, testClientCompare);
      testClientCompare.setResourceIds(Set.of("resource"));
      assertNotEquals(testClient, testClientCompare);
    }

    @Test
    void testEqualRegisteredRedirectUris() {
      assertEquals(testClient, testClientCompare);
      testClientCompare.setRegisteredRedirectUri(Set.of("http://localhost:8080/uaa"));
      assertNotEquals(testClient, testClientCompare);
    }

    @Test
    void testEqualSecret() {
      assertEquals(testClient, testClientCompare);
      testClientCompare.setClientSecret("secret");
      assertNotEquals(testClient, testClientCompare);
    }

    @Test
    void testEqualClientId() {
      assertEquals(testClient, testClientCompare);
      testClientCompare.setClientId("user");
      assertNotEquals(testClient, testClientCompare);
    }

    @Test
    void testEqualAuthorizedGrantTypes() {
      assertEquals(testClient, testClientCompare);
      testClientCompare.setAuthorizedGrantTypes(Set.of("client_credentials"));
      assertNotEquals(testClient, testClientCompare);
    }

    @Test
    void testEqualAuthorities() {
      assertEquals(testClient, testClientCompare);
      testClientCompare.setAuthorities(AuthorityUtils.createAuthorityList("none"));
      assertNotEquals(testClient, testClientCompare);
    }

    @Test
    void testEqualRefreshTokenValiditySeconds() {
      assertEquals(testClient, testClientCompare);
      testClientCompare.setRefreshTokenValiditySeconds(1);
      assertNotEquals(testClient, testClientCompare);
    }

    @Test
    void testEqualAccessTokenValiditySeconds() {
      assertEquals(testClient, testClientCompare);
      testClientCompare.setAccessTokenValiditySeconds(1);
      assertNotEquals(testClient, testClientCompare);
    }

  }
}