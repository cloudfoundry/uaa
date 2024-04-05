package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.provider.ClientAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for InMemoryClientDetailsService
 */
class InMemoryClientDetailsServiceTest {

  private final InMemoryClientDetailsService inMemoryClientDetailsService = new InMemoryClientDetailsService();
  @BeforeEach
  void setUp() {
    UaaClientDetails uaaClientDetails = new UaaClientDetails("admin", "uaa", "uaa.none",
        "client_credentials", "none", "http://localhost:8080/uaa");
    inMemoryClientDetailsService.setClientDetailsStore(Map.of("admin", uaaClientDetails));
  }

  @Test
  void loadClientByClientId() {
    UaaClientDetails uaaClientDetails = inMemoryClientDetailsService.loadClientByClientId("admin");
    assertEquals("admin", uaaClientDetails.getClientId());
    assertEquals("uaa", uaaClientDetails.getResourceIds().iterator().next());
    assertEquals("client_credentials", uaaClientDetails.getAuthorizedGrantTypes().iterator().next());
    assertEquals("none", uaaClientDetails.getAuthorities().iterator().next().getAuthority());
    assertEquals("http://localhost:8080/uaa", uaaClientDetails.getRegisteredRedirectUri().iterator().next());
    assertEquals("uaa.none", uaaClientDetails.getScope().iterator().next());
  }

  @Test
  void addClientDetails() {
    inMemoryClientDetailsService.addClientDetails(new UaaClientDetails("user", null, null, null, null));
    UaaClientDetails uaaClientDetails = inMemoryClientDetailsService.loadClientByClientId("user");
    assertEquals("user", uaaClientDetails.getClientId());
  }

  @Test
  void addClientDetailsNull() {
    assertThrows(ClientRegistrationException.class, () -> inMemoryClientDetailsService.addClientDetails(null));
  }

  @Test
  void addClientDetailsButExistsAlready() {
    assertThrows(ClientAlreadyExistsException.class, () -> inMemoryClientDetailsService.addClientDetails(new UaaClientDetails("admin", null, null, null, null)));
  }

  @Test
  void addClientDetailsButDoesNotExist() {
    assertThrows(NoSuchClientException.class, () -> inMemoryClientDetailsService.loadClientByClientId(("user")));
  }
}