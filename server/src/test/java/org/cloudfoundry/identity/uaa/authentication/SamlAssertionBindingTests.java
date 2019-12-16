/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.ws.transport.http.HTTPInTransport;
import org.opensaml.xml.parse.BasicParserPool;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Created by fhanik on 12/22/16.
 */
public class SamlAssertionBindingTests {

    private SamlAssertionBinding binding;

    @Before
    public void setUp() {
        binding = new SamlAssertionBinding(new BasicParserPool());
    }

    @Test
    public void supports() {
        HTTPInTransport transport = mock(HTTPInTransport.class);
        assertFalse(binding.supports(transport));

        when(transport.getHTTPMethod()).thenReturn("POST");
        assertFalse(binding.supports(transport));

        when(transport.getParameterValue("assertion")).thenReturn("some assertion");
        assertTrue(binding.supports(transport));
    }

    @Test
    public void getBindingURI() {
        assertEquals("urn:oasis:names:tc:SAML:2.0:bindings:URI", binding.getBindingURI());
    }

}