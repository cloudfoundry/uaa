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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class CodeStoreEndpointsTests extends JdbcTestBase {

    private CodeStoreEndpoints codeStoreEndpoints;

    private ExpiringCodeStore expiringCodeStore;

    private TimeService timeService = new TimeServiceImpl();

    @Before
    public void initCodeStoreTests() throws Exception {
        codeStoreEndpoints = new CodeStoreEndpoints();
        expiringCodeStore = new JdbcExpiringCodeStore(jdbcTemplate.getDataSource(), timeService);
        codeStoreEndpoints.setExpiringCodeStore(expiringCodeStore);
    }

    @Test
    public void testGenerateCode() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, data, null);

        ExpiringCode result = codeStoreEndpoints.generateCode(expiringCode);

        assertNotNull(result);

        assertNotNull(result.getCode());
        assertTrue(result.getCode().trim().length() == 10);

        assertEquals(expiresAt, result.getExpiresAt());

        assertEquals(data, result.getData());
    }

    @Test
    public void testGenerateCodeWithNullData() throws Exception {
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, null, null);

        try {
            codeStoreEndpoints.generateCode(expiringCode);

            fail("code is null, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.BAD_REQUEST);
        }
    }

    @Test
    public void testGenerateCodeWithNullExpiresAt() throws Exception {
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
    public void testGenerateCodeWithExpiresAtInThePast() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() - 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, data, null);

        try {
            codeStoreEndpoints.generateCode(expiringCode);

            fail("expiresAt is in the past, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.BAD_REQUEST);
        }
    }

    @Test
    public void testGenerateCodeWithDuplicateCode() throws Exception {
        RandomValueStringGenerator generator = mock(RandomValueStringGenerator.class);
        when(generator.generate()).thenReturn("duplicate");
        expiringCodeStore.setGenerator(generator);

        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
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
    public void testRetrieveCode() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
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
    public void testRetrieveCodeWithCodeNotFound() throws Exception {
        try {
            codeStoreEndpoints.retrieveCode("unknown");

            fail("Non-existent code, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.NOT_FOUND);
        }
    }

    @Test
    public void testRetrieveCodeWithNullCode() throws Exception {
        try {
            codeStoreEndpoints.retrieveCode(null);

            fail("code is null, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.BAD_REQUEST);
        }
    }

    @Test
    public void testStoreLargeData() throws Exception {
        char[] oneMb = new char[1024 * 1024];
        Arrays.fill(oneMb, 'a');
        String data = new String(oneMb);
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, data, null);

        ExpiringCode generatedCode = codeStoreEndpoints.generateCode(expiringCode);

        String code = generatedCode.getCode();
        ExpiringCode actualCode = codeStoreEndpoints.retrieveCode(code);

        assertEquals(generatedCode, actualCode);
    }

    @Test
    public void testRetrieveCodeWithExpiredCode() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 1000);
        ExpiringCode expiringCode = new ExpiringCode(null, expiresAt, data, null);

        ExpiringCode generatedCode = codeStoreEndpoints.generateCode(expiringCode);

        Thread.currentThread();
        Thread.sleep(1001);

        try {
            codeStoreEndpoints.retrieveCode(generatedCode.getCode());

            fail("code is expired, should throw CodeStoreException.");
        } catch (CodeStoreException e) {
            assertEquals(e.getStatus(), HttpStatus.NOT_FOUND);
        }
    }
}
