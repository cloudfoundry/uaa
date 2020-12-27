package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.is;

@DefaultTestContext
class IdentityZoneEndpointsAopTests {

    @Autowired
    private IdentityZoneEndpoints identityZoneEndpoints;

    @Test
    void updateIdentityZone_WithObject() {
        assertThrowsWithMessageThat(
                AccessDeniedException.class,
                () -> identityZoneEndpoints.updateIdentityZone(IdentityZone.getUaa(), null),
                is("Access to UAA is not allowed."));
    }

    @Test
    void updateIdentityZone_WithId() {
        assertThrowsWithMessageThat(
                AccessDeniedException.class,
                () -> identityZoneEndpoints.updateIdentityZone(null, IdentityZone.getUaaZoneId()),
                is("Access to UAA is not allowed."));
    }

    @Test
    void createClient() {
        assertThrowsWithMessageThat(
                AccessDeniedException.class,
                () -> identityZoneEndpoints.createClient(IdentityZone.getUaaZoneId(), null),
                is("Access to UAA is not allowed."));
    }

    @Test
    void deleteClient() {
        assertThrowsWithMessageThat(
                AccessDeniedException.class,
                () -> identityZoneEndpoints.deleteClient(IdentityZone.getUaaZoneId(), null),
                is("Access to UAA is not allowed."));
    }

}