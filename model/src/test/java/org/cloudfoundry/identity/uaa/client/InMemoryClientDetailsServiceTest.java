package org.cloudfoundry.identity.uaa.client;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.cloudfoundry.identity.uaa.provider.ClientAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.ClientRegistrationException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
        assertThat(uaaClientDetails.getClientId()).isEqualTo("admin");
        assertThat(uaaClientDetails.getResourceIds().iterator().next()).isEqualTo("uaa");
        assertThat(uaaClientDetails.getAuthorizedGrantTypes().iterator().next()).isEqualTo("client_credentials");
        assertThat(uaaClientDetails.getAuthorities().iterator().next().getAuthority()).isEqualTo("none");
        assertThat(uaaClientDetails.getRegisteredRedirectUri().iterator().next()).isEqualTo("http://localhost:8080/uaa");
        assertThat(uaaClientDetails.getScope().iterator().next()).isEqualTo("uaa.none");
    }

    @Test
    void addClientDetails() {
        inMemoryClientDetailsService.addClientDetails(new UaaClientDetails("user", null, null, null, null));
        UaaClientDetails uaaClientDetails = inMemoryClientDetailsService.loadClientByClientId("user");
        assertThat(uaaClientDetails.getClientId()).isEqualTo("user");
    }

    @Test
    void addClientDetailsNull() {
        assertThatThrownBy(() -> inMemoryClientDetailsService.addClientDetails(null)).asInstanceOf(InstanceOfAssertFactories.throwable(ClientRegistrationException.class));
    }

    @Test
    void addClientDetailsButExistsAlready() {
        assertThatThrownBy(() -> inMemoryClientDetailsService.addClientDetails(new UaaClientDetails("admin", null, null, null, null))).asInstanceOf(InstanceOfAssertFactories.throwable(ClientAlreadyExistsException.class));
    }

    @Test
    void addClientDetailsButDoesNotExist() {
        assertThatThrownBy(() -> inMemoryClientDetailsService.loadClientByClientId("user")).asInstanceOf(InstanceOfAssertFactories.throwable(NoSuchClientException.class));
    }
}