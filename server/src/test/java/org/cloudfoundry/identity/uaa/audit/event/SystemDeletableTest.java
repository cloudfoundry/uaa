package org.cloudfoundry.identity.uaa.audit.event;

import org.slf4j.Logger;
import org.cloudfoundry.identity.uaa.mfa.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class SystemDeletableTest {

    private SystemDeletable deletable = mock(SystemDeletable.class);
    private Authentication authentication = mock(Authentication.class);
    private IdentityZone zone;

    @BeforeEach
    void setup() {
        zone = MultitenancyFixture.identityZone("zone-id", "zone");
        IdentityZoneHolder.set(zone);
        resetDeletable();
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    @Test
    void ignore_unknown_events() {
        AbstractUaaEvent event = mock(AbstractUaaEvent.class);
        deletable.onApplicationEvent(event);
        verify(deletable, never()).onApplicationEvent(any(EntityDeletedEvent.class));
        verify(deletable, never()).deleteByIdentityZone(any());
        verify(deletable, never()).deleteByOrigin(any(),any());
        verify(deletable, never()).deleteByClient(any(),any());
        verify(deletable, never()).deleteByUser(any(),any());
    }

    @Test
    void uaa_default_zone_is_ignored() {
        EntityDeletedEvent event = new EntityDeletedEvent(IdentityZone.getUaa(), authentication);
        deletable.onApplicationEvent(event);
        verify(deletable, never()).deleteByIdentityZone(any());
        verify(deletable, never()).deleteByOrigin(any(),any());
        verify(deletable, never()).deleteByClient(any(),any());
        verify(deletable, never()).deleteByUser(any(),any());
    }

    @Test
    void zone_event_received() {

        EntityDeletedEvent event = new EntityDeletedEvent(zone, authentication);
        deletable.onApplicationEvent(event);
        verify(deletable, times(1)).deleteByIdentityZone("zone-id");
        verify(deletable, never()).deleteByOrigin(any(),any());
        verify(deletable, never()).deleteByClient(any(),any());
        verify(deletable, never()).deleteByUser(any(),any());
    }

    @Test
    void provider_event_received() {
        IdentityProvider provider = new IdentityProvider();
        provider.setId("id").setIdentityZoneId("other-zone-id").setOriginKey("origin");
        EntityDeletedEvent event = new EntityDeletedEvent(provider, authentication);
        deletable.onApplicationEvent(event);
        verify(deletable, never()).deleteByIdentityZone(any());
        verify(deletable, times(1)).deleteByOrigin("origin","other-zone-id");
        verify(deletable, never()).deleteByClient(any(),any());
        verify(deletable, never()).deleteByUser(any(),any());
    }

    @Test
    void client_event_received() {
        BaseClientDetails client = new BaseClientDetails("clientId", "", "", "client_credentials", "uaa.none");
        EntityDeletedEvent<ClientDetails> event = new EntityDeletedEvent(client, authentication);
        for (IdentityZone zone : Arrays.asList(this.zone, IdentityZone.getUaa())) {
            resetDeletable();
            IdentityZoneHolder.set(zone);
            deletable.onApplicationEvent(event);
            verify(deletable, never()).deleteByIdentityZone(any());
            verify(deletable, never()).deleteByOrigin(any(), any());
            verify(deletable, times(1)).deleteByClient(client.getClientId(), zone.getId());
            verify(deletable, never()).deleteByUser(any(), any());
        }
    }

    @Test
    void user_event_received() {
        UaaUser uaaUser = new UaaUser(new UaaUserPrototype()
                                       .withUsername("username")
                                       .withId("uaaUser-id")
                                       .withZoneId("other-zone-id")
                                       .withEmail("test@test.com")
        );
        ScimUser scimUser = new ScimUser(uaaUser.getId(), uaaUser.getUsername(), uaaUser.getGivenName(), uaaUser.getFamilyName());
        scimUser.setPrimaryEmail(uaaUser.getEmail());
        scimUser.setZoneId(uaaUser.getZoneId());

        for (Object user : Arrays.asList(uaaUser, scimUser)) {
            for (IdentityZone zone : Arrays.asList(this.zone, IdentityZone.getUaa())) {
                resetDeletable();
                IdentityZoneHolder.set(zone);
                EntityDeletedEvent<UaaUser> event = new EntityDeletedEvent(user, authentication);
                deletable.onApplicationEvent(event);
                verify(deletable, never()).deleteByIdentityZone(any());
                verify(deletable, never()).deleteByOrigin(any(), any());
                verify(deletable, never()).deleteByClient(any(), any());
                verify(deletable, times(1)).deleteByUser(uaaUser.getId(), uaaUser.getZoneId());
            }
        }
    }

    @Test
    void mfa_event_received() {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = new MfaProvider<GoogleMfaProviderConfig>().setId("provider1");
        EntityDeletedEvent<MfaProvider> event = new EntityDeletedEvent<>(mfaProvider, authentication);
        deletable.onApplicationEvent(event);
        verify(deletable, never()).deleteByIdentityZone(any());
        verify(deletable, never()).deleteByOrigin(any(), any());
        verify(deletable, never()).deleteByClient(any(), any());
        verify(deletable, never()).deleteByUser(any(), any());
        verify(deletable, times(1)).deleteByMfaProvider(eq("provider1"), any());
    }

    void resetDeletable() {
        reset(deletable);
        doCallRealMethod().when(deletable).onApplicationEvent(any(EntityDeletedEvent.class));
        doCallRealMethod().when(deletable).onApplicationEvent(any(AbstractUaaEvent.class));
        doCallRealMethod().when(deletable).isUaaZone(any());
        when(deletable.getLogger()).thenReturn(mock(Logger.class));
    }
}