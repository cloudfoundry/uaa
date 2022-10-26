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

import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EntityDeletedEventTest {

    private String randomId;

    @BeforeEach
    void setUp() {
        randomId = new RandomValueStringGenerator().generate();
    }

    @Test
    void getAuditEvent_IdentityProvider() {
        IdentityProvider mockIdentityProvider = mock(IdentityProvider.class);
        when(mockIdentityProvider.getId()).thenReturn(randomId);

        checkAuditEventData(mockIdentityProvider, IdentityProvider.class, randomId);
    }

    @Test
    void getAuditEvent_IdentityZone() {
        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        when(mockIdentityZone.getId()).thenReturn(randomId);

        checkAuditEventData(mockIdentityZone, IdentityZone.class, randomId);
    }

    @Test
    void getAuditEvent_BaseClientDetails() {
        BaseClientDetails mockBaseClientDetails = mock(BaseClientDetails.class);
        when(mockBaseClientDetails.getClientId()).thenReturn(randomId);

        checkAuditEventData(mockBaseClientDetails, BaseClientDetails.class, randomId);
    }

    @Test
    void getAuditEvent_UaaUser() {
        UaaUser mockUaaUser = mock(UaaUser.class);
        when(mockUaaUser.getId()).thenReturn(randomId);

        checkAuditEventData(mockUaaUser, UaaUser.class, randomId);
    }

    @Test
    void getAuditEvent_ScimUser() {
        ScimUser mockScimUser = mock(ScimUser.class);
        when(mockScimUser.getId()).thenReturn(randomId);

        checkAuditEventData(mockScimUser, ScimUser.class, randomId);
    }

    private static <T> void checkAuditEventData(T deleted, Class<T> clazz, String id) {
        EntityDeletedEvent<T> event = new EntityDeletedEvent<>(
                deleted,
                mock(Authentication.class),
                null);
        assertEquals(
                "Class:" + clazz.getName() + "; ID:" + id,
                event.getAuditEvent().getData());
    }

}