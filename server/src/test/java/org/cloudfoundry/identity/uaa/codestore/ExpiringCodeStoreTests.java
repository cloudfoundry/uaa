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
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.Mockito;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class ExpiringCodeStoreTests extends JdbcTestBase {

    private ExpiringCodeStore expiringCodeStore;
    private Class expiringCodeStoreClass;

    public ExpiringCodeStoreTests(Class expiringCodeStoreClass) {
        this.expiringCodeStoreClass = expiringCodeStoreClass;
    }

    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][] {
                        { InMemoryExpiringCodeStore.class }, { JdbcExpiringCodeStore.class },
        });
    }

    @Before
    public void initExpiringCodeStoreTests() throws Exception {
        expiringCodeStore = (ExpiringCodeStore) expiringCodeStoreClass.newInstance();

        if (expiringCodeStore instanceof InMemoryExpiringCodeStore) {

        } else {
            // confirm that everything is clean prior to test.
            TestUtils.deleteFrom(jdbcTemplate.getDataSource(), JdbcExpiringCodeStore.tableName);
            if (expiringCodeStore instanceof JdbcExpiringCodeStore) {
                ((JdbcExpiringCodeStore) expiringCodeStore).setDataSource(jdbcTemplate.getDataSource());
            }
        }
    }

    @Test
    public void testGenerateCode() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode expiringCode = expiringCodeStore.generateCode(data, expiresAt, null);

        Assert.assertNotNull(expiringCode);

        Assert.assertNotNull(expiringCode.getCode());
        Assert.assertTrue(expiringCode.getCode().trim().length() > 0);

        Assert.assertEquals(expiresAt, expiringCode.getExpiresAt());

        Assert.assertEquals(data, expiringCode.getData());
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateCodeWithNullData() throws Exception {
        String data = null;
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        expiringCodeStore.generateCode(data, expiresAt, null);
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateCodeWithNullExpiresAt() throws Exception {
        String data = "{}";
        Timestamp expiresAt = null;
        expiringCodeStore.generateCode(data, expiresAt, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateCodeWithExpiresAtInThePast() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() - 60000);
        expiringCodeStore.generateCode(data, expiresAt, null);
    }

    @Test(expected = DataIntegrityViolationException.class)
    public void testGenerateCodeWithDuplicateCode() throws Exception {
        RandomValueStringGenerator generator = Mockito.mock(RandomValueStringGenerator.class);
        Mockito.when(generator.generate()).thenReturn("duplicate");
        expiringCodeStore.setGenerator(generator);

        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        expiringCodeStore.generateCode(data, expiresAt, null);
        expiringCodeStore.generateCode(data, expiresAt, null);
    }

    @Test
    public void testRetrieveCode() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null);

        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode());

        Assert.assertEquals(generatedCode, retrievedCode);

        Assert.assertNull(expiringCodeStore.retrieveCode(generatedCode.getCode()));
    }

    @Test
    public void testRetrieveCodeWithCodeNotFound() throws Exception {
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode("unknown");

        Assert.assertNull(retrievedCode);
    }

    @Test(expected = NullPointerException.class)
    public void testRetrieveCodeWithNullCode() throws Exception {
        expiringCodeStore.retrieveCode(null);
    }

    @Test
    public void testStoreLargeData() throws Exception {
        char[] oneMb = new char[1024 * 1024];
        Arrays.fill(oneMb, 'a');
        String aaaString = new String(oneMb);
        ExpiringCode expiringCode = expiringCodeStore.generateCode(aaaString, new Timestamp(
                        System.currentTimeMillis() + 60000), null);
        String code = expiringCode.getCode();
        ExpiringCode actualCode = expiringCodeStore.retrieveCode(code);
        Assert.assertEquals(expiringCode, actualCode);
    }

    @Test
    public void testExpiredCodeReturnsNull() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 1000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null);
        Thread.currentThread();
        Thread.sleep(1001);
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode());
        Assert.assertNull(retrievedCode);
    }

    @Test
    public void testExpireCodeByIntent() throws Exception {
        ExpiringCode code = expiringCodeStore.generateCode("{}", new Timestamp(System.currentTimeMillis() + 60000), "Test Intent");

        expiringCodeStore.expireByIntent("Test Intent");

        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(code.getCode());

        Assert.assertNull(retrievedCode);
    }

    @Test
    public void testDatabaseDown() throws Exception {
        if (JdbcExpiringCodeStore.class == expiringCodeStoreClass) {
            javax.sql.DataSource ds = Mockito.mock(javax.sql.DataSource.class);
            Mockito.when(ds.getConnection()).thenThrow(new SQLException());
            ((JdbcExpiringCodeStore) expiringCodeStore).setDataSource(ds);
            try {
                String data = "{}";
                Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 10000000);
                ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null);
                Assert.fail("Database is down, should not generate a code");
            } catch (DataAccessException x) {

            }
        }

    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void testExpirationCleaner() throws Exception {
        if (JdbcExpiringCodeStore.class == expiringCodeStoreClass) {
            jdbcTemplate.update(JdbcExpiringCodeStore.insert, "test", System.currentTimeMillis() - 1000, "{}", null);
            ((JdbcExpiringCodeStore) expiringCodeStore).cleanExpiredEntries();
            jdbcTemplate.queryForObject(JdbcExpiringCodeStore.select,
                            new JdbcExpiringCodeStore.JdbcExpiringCodeMapper(), "test");
        } else {
            throw new EmptyResultDataAccessException(1);
        }

    }
}
