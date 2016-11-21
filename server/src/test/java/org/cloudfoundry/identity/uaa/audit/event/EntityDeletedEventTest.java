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
import org.cloudfoundry.identity.uaa.provider.IdentityProviderValidationRequest;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.Before;
import org.junit.Test;

import static org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent.dataFormat;
import static org.junit.Assert.assertEquals;

public class EntityDeletedEventTest {


    private IdentityProvider provider;
    private IdentityZone zone;

    @Before
    public void setup() throws Exception {
        provider = new IdentityProvider();
        provider.setId("id");

        zone = IdentityZone.getUaa();
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

    public void evalute(Object o, String expected) {
        EntityDeletedEvent<Object> event = new EntityDeletedEvent(o, new IdentityProviderValidationRequest.UsernamePasswordAuthentication("username","password"));
        assertEquals(expected, event.getAuditEvent().getData());
    }
}