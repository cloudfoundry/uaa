/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.util.ReflectionTestUtils;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

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

    public int countCodes() {
        if (expiringCodeStore instanceof InMemoryExpiringCodeStore) {
            Map map = (Map) ReflectionTestUtils.getField(expiringCodeStore, "store");
            return map.size();
        } else {
            // confirm that everything is clean prior to test.
            return jdbcTemplate.queryForObject("select count(*) from expiring_code_store", Integer.class);
        }
    }

    @Test
    public void testGenerateCode() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode expiringCode = expiringCodeStore.generateCode(data, expiresAt);

        assertNotNull(expiringCode);

        assertNotNull(expiringCode.getCode());
        assertTrue(expiringCode.getCode().trim().length() > 0);

        assertEquals(expiresAt, expiringCode.getExpiresAt());

        assertEquals(data, expiringCode.getData());
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateCodeWithNullData() throws Exception {
        String data = null;
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        expiringCodeStore.generateCode(data, expiresAt);
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateCodeWithNullExpiresAt() throws Exception {
        String data = "{}";
        Timestamp expiresAt = null;
        expiringCodeStore.generateCode(data, expiresAt);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateCodeWithExpiresAtInThePast() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() - 60000);
        expiringCodeStore.generateCode(data, expiresAt);
    }

    @Test(expected = DataIntegrityViolationException.class)
    public void testGenerateCodeWithDuplicateCode() throws Exception {
        RandomValueStringGenerator generator = mock(RandomValueStringGenerator.class);
        when(generator.generate()).thenReturn("duplicate");
        expiringCodeStore.setGenerator(generator);

        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        expiringCodeStore.generateCode(data, expiresAt);
        expiringCodeStore.generateCode(data, expiresAt);
    }

    @Test
    public void testRetrieveCode() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt);

        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode());

        assertEquals(generatedCode, retrievedCode);

        assertNull(expiringCodeStore.retrieveCode(generatedCode.getCode()));
    }

    @Test
    public void testRetrieveCode_In_Another_Zone() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt);

        IdentityZoneHolder.set(MultitenancyFixture.identityZone("other", "other"));
        Assert.assertNull(expiringCodeStore.retrieveCode(generatedCode.getCode()));

        IdentityZoneHolder.clear();
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode());
        Assert.assertEquals(generatedCode, retrievedCode);


    }

    @Test
    public void testRetrieveCodeWithCodeNotFound() throws Exception {
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode("unknown");

        assertNull(retrievedCode);
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
            System.currentTimeMillis() + 60000));
        String code = expiringCode.getCode();
        ExpiringCode actualCode = expiringCodeStore.retrieveCode(code);
        assertEquals(expiringCode, actualCode);
    }

    @Test
    public void testExpiredCodeReturnsNull() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 1000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt);
        Thread.currentThread();
        Thread.sleep(1001);
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode());
        assertNull(retrievedCode);
    }

    @Test
    public void testDatabaseDown() throws Exception {
        if (JdbcExpiringCodeStore.class == expiringCodeStoreClass) {
            javax.sql.DataSource ds = mock(javax.sql.DataSource.class);
            when(ds.getConnection()).thenThrow(new SQLException());
            ((JdbcExpiringCodeStore) expiringCodeStore).setDataSource(ds);
            try {
                String data = "{}";
                Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 10000000);
                ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt);
                fail("Database is down, should not generate a code");
            } catch (DataAccessException x) {

            }
        }

    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void testExpirationCleaner() throws Exception {
        if (JdbcExpiringCodeStore.class == expiringCodeStoreClass) {
            jdbcTemplate.update(JdbcExpiringCodeStore.insert, "test", System.currentTimeMillis() - 1000, "{}");
            ((JdbcExpiringCodeStore) expiringCodeStore).cleanExpiredEntries();
            jdbcTemplate.queryForObject(JdbcExpiringCodeStore.select,
                                        (RowMapper<ExpiringCode>) ReflectionTestUtils.getField(expiringCodeStore, "rowMapper"), "test");
        } else {
            throw new EmptyResultDataAccessException(1);
        }

    }
}
