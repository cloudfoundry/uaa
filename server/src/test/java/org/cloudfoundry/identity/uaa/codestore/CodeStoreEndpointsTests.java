/*******************************************************************************
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
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CodeStoreEndpointsTests extends JdbcTestBase {

    private CodeStoreEndpoints codeStoreEndpoints;
    private ExpiringCodeStore expiringCodeStore;
    private AtomicLong currentTime;

    @Before
    public void initCodeStoreTests() {
        codeStoreEndpoints = new CodeStoreEndpoints();
        currentTime = new AtomicLong(System.currentTimeMillis());

        expiringCodeStore = new JdbcExpiringCodeStore(jdbcTemplate.getDataSource(), new TimeService() {
            @Override
            public long getCurrentTimeMillis() {
                return currentTime.get();
            }
        });
        codeStoreEndpoints.setExpiringCodeStore(expiringCodeStore);
    }

    @Test
    public void testGenerateCode() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, data, null);

        ExpiringCode result = codeStoreEndpoints.generateCode(expiringCode);

        assertNotNull(result);

        assertNotNull(result.getCode());
        assertTrue(result.getCode().trim().length() == 10);

        assertEquals(expiresAt, result.getExpiresAt());

        assertEquals(data, result.getData());
    }

    @Test
    public void testGenerateCodeWithNullData() {
        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, null, null);

        try {
            codeStoreEndpoints.generateCode(expiringCode);

            fail("code is null, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.BAD_REQUEST);
        }
    }

    @Test
    public void testGenerateCodeWithNullExpiresAt() {
        String data = "{}";
        ExpiringCode expiringCode = new ExpiringCode(null, null, data, null);

        try {
            codeStoreEndpoints.generateCode(expiringCode);

            fail("expiresAt is null, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.BAD_REQUEST);
        }
    }

    @Test
    public void testGenerateCodeWithExpiresAtInThePast() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(currentTime.get() - 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, data, null);

        try {
            codeStoreEndpoints.generateCode(expiringCode);

            fail("expiresAt is in the past, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.BAD_REQUEST);
        }
    }

    @Test
    public void testGenerateCodeWithDuplicateCode() {
        RandomValueStringGenerator generator = mock(RandomValueStringGenerator.class);
        when(generator.generate()).thenReturn("duplicate");
        expiringCodeStore.setGenerator(generator);

        String data = "{}";
        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, data, null);

        try {
            codeStoreEndpoints.generateCode(expiringCode);
            codeStoreEndpoints.generateCode(expiringCode);

            fail("duplicate code generated, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Test
    public void testRetrieveCode() {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, data, null);
        ExpiringCode generatedCode = codeStoreEndpoints.generateCode(expiringCode);

        ExpiringCode retrievedCode = codeStoreEndpoints.retrieveCode(generatedCode.getCode());

        assertEquals(generatedCode, retrievedCode);

        try {
            codeStoreEndpoints.retrieveCode(generatedCode.getCode());

            fail("One-use code already retrieved, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.NOT_FOUND);
        }
    }

    @Test
    public void testRetrieveCodeWithCodeNotFound() {
        try {
            codeStoreEndpoints.retrieveCode("unknown");

            fail("Non-existent code, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.NOT_FOUND);
        }
    }

    @Test
    public void testRetrieveCodeWithNullCode() {
        try {
            codeStoreEndpoints.retrieveCode(null);

            fail("code is null, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.BAD_REQUEST);
        }
    }

    @Test
    public void testStoreLargeData() {
        char[] oneMb = new char[1024 * 1024];
        Arrays.fill(oneMb, 'a');
        String data = new String(oneMb);
        Timestamp expiresAt = new Timestamp(currentTime.get() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, data, null);

        ExpiringCode generatedCode = codeStoreEndpoints.generateCode(expiringCode);

        String code = generatedCode.getCode();
        ExpiringCode actualCode = codeStoreEndpoints.retrieveCode(code);

        assertEquals(generatedCode, actualCode);
    }

    @Test
    public void testRetrieveCodeWithExpiredCode() {
        String data = "{}";
        int expiresIn = 1000;
        Timestamp expiresAt = new Timestamp(currentTime.get() + expiresIn);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, data, null);

        ExpiringCode generatedCode = codeStoreEndpoints.generateCode(expiringCode);
        currentTime.addAndGet(expiresIn + 1);

        try {
            codeStoreEndpoints.retrieveCode(generatedCode.getCode());

            fail("code is expired, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.NOT_FOUND);
        }
    }
}
