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
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doCallRealMethod;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SystemDeletableTest {

    SystemDeletable deletable = mock(SystemDeletable.class);
    Authentication authentication = mock(Authentication.class);

    @Before
    public void setup() throws Exception {
        doCallRealMethod().when(deletable).onApplicationEvent(any(EntityDeletedEvent.class));
        when(deletable.getLogger()).thenReturn(mock(Log.class));
    }

    @Test
    public void zone_event_received() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone("id","zone");
        EntityDeletedEvent event = new EntityDeletedEvent(zone, authentication);
        deletable.onApplicationEvent(event);
        verify(deletable, times(1)).deleteByIdentityZone("id");
    }

    @Test
    public void onApplicationEvent1() throws Exception {

    }

}