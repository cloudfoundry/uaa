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

package org.cloudfoundry.identity.uaa.util;

import java.util.concurrent.BlockingQueue;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.when;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.util.ReflectionTestUtils;

public class LowConcurrencyPasswordEncoderTests {


    private PasswordEncoder delegate;
    private long timeout = 10000;
    private String password = new RandomValueStringGenerator(24).generate();
    private Runtime runtime;
    private LowConcurrencyPasswordEncoder encoder;

    @Rule
    public ExpectedException exception = ExpectedException.none();


    @Before
    public void setup() throws Exception {
        delegate = new BCryptPasswordEncoder();
        runtime = mock(Runtime.class);
        setProcessorCount(Runtime.getRuntime().availableProcessors());
    }

    @After
    public void teardown() throws Exception {
        stillWorking();
    }

    public void setProcessorCount(int availableProcessors) {
        reset(runtime);
        when(runtime.availableProcessors()).thenReturn(availableProcessors);
        encoder = new LowConcurrencyPasswordEncoder(delegate, timeout, true, runtime);
    }

    @Test
    public void waiters_returns_null() throws Exception {
        setProcessorCount(1);
        assertEquals(0, encoder.getWaiters());
    }

    @Test
    public void timeout_throws_auth_exception() throws Exception {
        exception.expect(AuthenticationServiceException.class);
        exception.expectMessage("System resources busy. Try again.");
        BlockingQueue queue = mock(BlockingQueue.class);
        setProcessorCount(1);
        ReflectionTestUtils.setField(encoder, "exchange", queue);
        try {
            stillWorking();
        } finally {
            //reset
            setProcessorCount(1);
        }
    }

    @Test
    public void enabled() throws Exception {
        assertNotNull(encoder);
        assertNotNull(ReflectionTestUtils.getField(encoder, "exchange"));
    }

    @Test
    public void disabled() throws Exception {
        encoder = new LowConcurrencyPasswordEncoder(delegate, timeout, false, runtime);
        assertNotNull(encoder);
        assertNull(ReflectionTestUtils.getField(encoder, "exchange"));
        assertEquals(0, encoder.getWaiters());
        assertEquals(-1, encoder.getCurrent());
    }

    public void stillWorking() throws Exception {
        assertTrue(encoder.matches(password, encoder.encode(password)));
    }

    @Test
    public void one_cpu_system() throws Exception {
        setProcessorCount(1);
        assertEquals(1, encoder.getMax());
    }

    @Test
    public void two_cpu_system() throws Exception {
        setProcessorCount(2);
        assertEquals(1, encoder.getMax());
    }

    @Test
    public void four_cpu_system() throws Exception {
        setProcessorCount(4);
        assertEquals(3, encoder.getMax());
    }

    @Test
    public void six_cpu_system() throws Exception {
        setProcessorCount(6);
        assertEquals(4, encoder.getMax());
    }

    @Test
    public void eight_cpu_system() throws Exception {
        setProcessorCount(8);
        assertEquals(6, encoder.getMax());
    }

    @Test
    public void twelve_cpu_system() throws Exception {
        setProcessorCount(12);
        assertEquals(10, encoder.getMax());
    }

}