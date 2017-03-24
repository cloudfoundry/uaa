/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.audit.event;

import org.apache.commons.logging.Log;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SystemDeletableTest {

    SystemDeletable deletable = mock(SystemDeletable.class);
    Authentication authentication = mock(Authentication.class);
    private IdentityZone zone;

    @Before
    public void setup() throws Exception {
        zone = MultitenancyFixture.identityZone("zone-id", "zone");
        IdentityZoneHolder.set(zone);
        resetDeletable();
    }

    @After
    public void tearDown() throws Exception {
        IdentityZoneHolder.clear();
    }

    @Test
    public void ignore_unknown_events() throws Exception {
        AbstractUaaEvent event = mock(AbstractUaaEvent.class);
        deletable.onApplicationEvent(event);
        verify(deletable, never()).onApplicationEvent(any(EntityDeletedEvent.class));
        verify(deletable, never()).deleteByIdentityZone(any());
        verify(deletable, never()).deleteByOrigin(any(),any());
        verify(deletable, never()).deleteByClient(any(),any());
        verify(deletable, never()).deleteByUser(any(),any());
    }

    @Test
    public void uaa_default_zone_is_ignored() throws Exception {
        EntityDeletedEvent event = new EntityDeletedEvent(IdentityZone.getUaa(), authentication);
        deletable.onApplicationEvent(event);
        verify(deletable, never()).deleteByIdentityZone(any());
        verify(deletable, never()).deleteByOrigin(any(),any());
        verify(deletable, never()).deleteByClient(any(),any());
        verify(deletable, never()).deleteByUser(any(),any());
    }

    @Test
    public void zone_event_received() throws Exception {

        EntityDeletedEvent event = new EntityDeletedEvent(zone, authentication);
        deletable.onApplicationEvent(event);
        verify(deletable, times(1)).deleteByIdentityZone("zone-id");
        verify(deletable, never()).deleteByOrigin(any(),any());
        verify(deletable, never()).deleteByClient(any(),any());
        verify(deletable, never()).deleteByUser(any(),any());
    }

    @Test
    public void provider_event_received() throws Exception {
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
    public void client_event_received() throws Exception {
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
    public void user_event_received() throws Exception {
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

    public void resetDeletable() {
        reset(deletable);
        doCallRealMethod().when(deletable).onApplicationEvent(any(EntityDeletedEvent.class));
        doCallRealMethod().when(deletable).onApplicationEvent(any(AbstractUaaEvent.class));
        doCallRealMethod().when(deletable).isUaaZone(any());
        when(deletable.getLogger()).thenReturn(mock(Log.class));
    }

    @Test
    public void onApplicationEvent1() throws Exception {

    }

}