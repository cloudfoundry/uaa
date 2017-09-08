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

package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.saml.storage.SAMLMessageStorage;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;

public class SamlSessionStorageFactoryTests {


    private SamlSessionStorageFactory factory;
    private MockHttpServletRequest request;

    @Before
    public void setUp() throws Exception {
        request = new MockHttpServletRequest();
        factory = new SamlSessionStorageFactory();
    }

    @After
    public void tearDown() throws Exception {
        IdentityZoneHolder.clear();
    }

    @Test
    public void get_storage_creates_session() throws Exception {
        assertNull(request.getSession(false));
        factory.getMessageStorage(request);
        assertNotNull(request.getSession(false));
    }

    @Test
    public void reuse_storage_in_session() throws Exception {
        SAMLMessageStorage storage1 = factory.getMessageStorage(request);
        SAMLMessageStorage storage2 = factory.getMessageStorage(request);
        assertSame(storage1, storage2);
    }

    @Test
    public void disable_message_storage() {
        IdentityZoneHolder.get().getConfig().getSamlConfig().setDisableInResponseToCheck(true);
        assertNull(factory.getMessageStorage(request));
    }

}