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

import org.junit.Before;
import org.junit.Test;
import org.opensaml.xml.XMLObject;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Arrays;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.mockito.Mockito.mock;

public class SamlMessageStorageTest {

    private SamlMessageStorage storage;
    private Map<String, XMLObject> messages;

    @Before
    public void setUp() throws Exception {
        storage = new SamlMessageStorage();
        messages = (Map<String, XMLObject>) ReflectionTestUtils.getField(storage, "messages");
    }

    @Test
    public void store_and_retrieve_message() throws Exception {
        XMLObject message = mock(XMLObject.class);
        assertEquals(0, messages.size());
        storage.storeMessage("id", message);
        storage.storeMessage("id1", message);
        assertEquals(2, messages.size());
        for (String id : Arrays.asList("id","id1")) {
            XMLObject xmlObject = storage.retrieveMessage(id);
            assertNotNull(xmlObject);
            assertSame(message, xmlObject);
            assertNull(storage.retrieveMessage(id));
        }
        assertEquals(0, messages.size());
    }



}