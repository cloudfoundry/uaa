package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DefaultTestContext
class IdentityZoneEndpointsAopTests {
    @Autowired
    private IdentityZoneEndpoints identityZoneEndpoints;

    @Test
    void updateIdentityZone_WithObject() {
        IdentityZone uaaZone = IdentityZone.getUaa();
        assertThatThrownBy(() -> identityZoneEndpoints.updateIdentityZone(uaaZone, null))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Access to UAA is not allowed.");
    }

    @Test
    void updateIdentityZone_WithId() {
        String uaaZoneId = IdentityZone.getUaaZoneId();
        assertThatThrownBy(() -> identityZoneEndpoints.updateIdentityZone(null, uaaZoneId))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Access to UAA is not allowed.");
    }

    @Test
    void createClient() {
        String uaaZoneId = IdentityZone.getUaaZoneId();
        assertThatThrownBy(() -> identityZoneEndpoints.createClient(uaaZoneId, null))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Access to UAA is not allowed.");
    }

    @Test
    void deleteClient() {
        String uaaZoneId = IdentityZone.getUaaZoneId();
        assertThatThrownBy(() -> identityZoneEndpoints.deleteClient(uaaZoneId, null))
                .isInstanceOf(AccessDeniedException.class)
                .hasMessage("Access to UAA is not allowed.");
    }
}
