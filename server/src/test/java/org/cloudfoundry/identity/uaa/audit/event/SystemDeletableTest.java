package org.cloudfoundry.identity.uaa.audit.event;

import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.Logger;
import org.springframework.security.core.Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;

import java.util.Arrays;

import static org.mockito.Mockito.*;

@ExtendWith(PollutionPreventionExtension.class)
class SystemDeletableTest {

    private SystemDeletable deletable;
    private Authentication authentication;

    @BeforeEach
    void setup() {
        deletable = mock(SystemDeletable.class);
        authentication = mock(Authentication.class);

        doCallRealMethod().when(deletable).onApplicationEvent(any(EntityDeletedEvent.class));
        when(deletable.getLogger()).thenReturn(mock(Logger.class));
    }

    @Test
    void ignoreUnknownEvents() {
        AbstractUaaEvent event = mock(AbstractUaaEvent.class);
        deletable.onApplicationEvent(event);
        verify(deletable, never()).onApplicationEvent(any(EntityDeletedEvent.class));
        verify(deletable, never()).deleteByIdentityZone(any());
        verify(deletable, never()).deleteByOrigin(any(), any());
        verify(deletable, never()).deleteByClient(any(), any());
        verify(deletable, never()).deleteByUser(any(), any());
    }

    @Test
    void uaaDefaultZoneIsIgnored() {
        EntityDeletedEvent event = new EntityDeletedEvent<>(IdentityZone.getUaa(), authentication, null);
        deletable.onApplicationEvent(event);
        verify(deletable, never()).deleteByIdentityZone(any());
        verify(deletable, never()).deleteByOrigin(any(), any());
        verify(deletable, never()).deleteByClient(any(), any());
        verify(deletable, never()).deleteByUser(any(), any());
    }

    @Test
    void identityZoneEventReceived() {
        IdentityZone zone = MultitenancyFixture.identityZone("zone-id", "zone");

        EntityDeletedEvent event = new EntityDeletedEvent<>(zone, authentication, null);
        deletable.onApplicationEvent(event);
        verify(deletable, times(1)).deleteByIdentityZone("zone-id");
        verify(deletable, never()).deleteByOrigin(any(), any());
        verify(deletable, never()).deleteByClient(any(), any());
        verify(deletable, never()).deleteByUser(any(), any());
    }

    @Test
    void identityProviderEventReceived() {
        IdentityProvider provider = new IdentityProvider();
        provider.setId("id").setIdentityZoneId("other-zone-id").setOriginKey("origin");
        EntityDeletedEvent event = new EntityDeletedEvent<>(provider, authentication, null);
        deletable.onApplicationEvent(event);
        verify(deletable, never()).deleteByIdentityZone(any());
        verify(deletable, times(1)).deleteByOrigin("origin", "other-zone-id");
        verify(deletable, never()).deleteByClient(any(), any());
        verify(deletable, never()).deleteByUser(any(), any());
    }

    @Test
    void clientDetailsEventReceived() {
        UaaClientDetails client = new UaaClientDetails("clientId", "", "", "client_credentials", "uaa.none");
        for (String zoneId : Arrays.asList("uaa", "zone1", "other-zone")) {
            EntityDeletedEvent<ClientDetails> event = new EntityDeletedEvent<>(client, authentication, zoneId);
            deletable.onApplicationEvent(event);
            verify(deletable, times(1)).deleteByClient(client.getClientId(), zoneId);
        }

        verify(deletable, never()).deleteByIdentityZone(any());
        verify(deletable, never()).deleteByOrigin(any(), any());
        verify(deletable, never()).deleteByUser(any(), any());
    }

    @Test
    void uaaUserEventReceived() {
        UaaUser uaaUser = new UaaUser(new UaaUserPrototype()
                .withUsername("username")
                .withId("uaaUser-id")
                .withZoneId("other-zone-id")
                .withEmail("test@test.com")
        );

        EntityDeletedEvent event = new EntityDeletedEvent<>(uaaUser, authentication, null);
        deletable.onApplicationEvent(event);
        verify(deletable, never()).deleteByIdentityZone(any());
        verify(deletable, never()).deleteByOrigin(any(), any());
        verify(deletable, never()).deleteByClient(any(), any());
        verify(deletable, times(1)).deleteByUser("uaaUser-id", "other-zone-id");
    }

    @Test
    void scimUserEventReceived() {
        ScimUser scimUser = new ScimUser(
                "scimUserId",
                null,
                null,
                null);
        scimUser.setZoneId("zoneId");

        EntityDeletedEvent event = new EntityDeletedEvent<>(scimUser, authentication, null);
        deletable.onApplicationEvent(event);
        verify(deletable, never()).deleteByIdentityZone(any());
        verify(deletable, never()).deleteByOrigin(any(), any());
        verify(deletable, never()).deleteByClient(any(), any());
        verify(deletable, times(1)).deleteByUser("scimUserId", "zoneId");
    }
}