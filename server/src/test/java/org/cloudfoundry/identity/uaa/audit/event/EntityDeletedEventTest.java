/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import static org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent.dataFormat;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;

public class EntityDeletedEventTest {


    private IdentityProvider provider;
    private IdentityZone zone;
    private BaseClientDetails client;
    private UaaUser uaaUser;
    private ScimUser scimUser;

    @Before
    public void setup() throws Exception {
        provider = new IdentityProvider();
        provider.setId("id");
        client = new BaseClientDetails("id", "", "", "", "");
        zone = IdentityZone.getUaa();
        uaaUser = new UaaUser(
            new UaaUserPrototype()
            .withId("user-id")
            .withUsername("username")
            .withEmail("test@test.com")
            .withZoneId(zone.getId())
        );
        scimUser = new ScimUser("id", "username", null, null);
        scimUser.setPrimaryEmail("test@test.com");
        scimUser.setZoneId(zone.getId());

    }

    @Test
    public void getAuditEvent_IdentityProvider() throws Exception {
        String expected = String.format(dataFormat, IdentityZone.class.getName(), zone.getId());
        evalute(zone, expected);
    }

    @Test
    public void getAuditEvent_IdentityZone() throws Exception {
        String expected = String.format(dataFormat, IdentityProvider.class.getName(), provider.getId());
        evalute(provider, expected);
    }

    @Test
    public void getAuditEvent_Client() throws Exception {
        String expected = String.format(dataFormat, BaseClientDetails.class.getName(), client.getClientId());
        evalute(client, expected);
    }

    @Test
    public void getAuditEvent_UaaUser() throws Exception {
        String expected = String.format(dataFormat, UaaUser.class.getName(), uaaUser.getId());
        evalute(uaaUser, expected);
    }
    @Test
    public void getAuditEvent_ScimUser() throws Exception {
        String expected = String.format(dataFormat, ScimUser.class.getName(), scimUser.getId());
        evalute(scimUser, expected);
    }

    public void evalute(Object o, String expected) {
        EntityDeletedEvent event = new EntityDeletedEvent(o, mock(Authentication.class));
        assertEquals(expected, event.getAuditEvent().getData());
    }
}