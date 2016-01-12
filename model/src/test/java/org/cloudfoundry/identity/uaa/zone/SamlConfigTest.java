/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SamlConfigTest {

    SamlConfig config;

    @Before
    public void setUp() {
        config = new SamlConfig();
    }

    @Test
    public void testIsRequestSigned() throws Exception {
        assertTrue(config.isRequestSigned());

    }

    @Test
    public void testIsWantAssertionSigned() throws Exception {
        assertFalse(config.isWantAssertionSigned());
    }

    @Test
    public void testSetPassphrase() {
        String passphrase = "password";
        config.setPrivateKeyPassword(passphrase);
        assertEquals(passphrase, config.getPrivateKeyPassword());
    }
}