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
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.util.TimeServiceImpl;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
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
import org.springframework.test.util.ReflectionTestUtils;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(Parameterized.class)
public class ExpiringCodeStoreTests extends JdbcTestBase {

    private ExpiringCodeStore expiringCodeStore;
    private Class expiringCodeStoreClass;
    private TimeService timeService = mock(TimeServiceImpl.class);

    public ExpiringCodeStoreTests(Class expiringCodeStoreClass) {
        this.expiringCodeStoreClass = expiringCodeStoreClass;
    }

    @Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
            {InMemoryExpiringCodeStore.class}, {JdbcExpiringCodeStore.class},
        });
    }

    @Before
    public void initExpiringCodeStoreTests() throws Exception {
        expiringCodeStore = (ExpiringCodeStore) expiringCodeStoreClass.newInstance();

        if (expiringCodeStore instanceof InMemoryExpiringCodeStore) {
            ((InMemoryExpiringCodeStore) expiringCodeStore).setTimeService(timeService);
        } else {
            // confirm that everything is clean prior to test.
            TestUtils.deleteFrom(jdbcTemplate, JdbcExpiringCodeStore.tableName);
            ((JdbcExpiringCodeStore) expiringCodeStore).setDataSource(jdbcTemplate.getDataSource());
            ((JdbcExpiringCodeStore) expiringCodeStore).setTimeService(timeService);
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
        ExpiringCode expiringCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());

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
        expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());
    }

    @Test(expected = NullPointerException.class)
    public void testGenerateCodeWithNullExpiresAt() throws Exception {
        String data = "{}";
        Timestamp expiresAt = null;
        expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());
    }

    @Test(expected = IllegalArgumentException.class)
    public void testGenerateCodeWithExpiresAtInThePast() throws Exception {
        long now = 100000L;
        when(timeService.getCurrentTimeMillis()).thenReturn(now);
        String data = "{}";
        Timestamp expiresAt = new Timestamp(now - 60000);
        expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());
    }

    @Test(expected = DataIntegrityViolationException.class)
    public void testGenerateCodeWithDuplicateCode() throws Exception {
        RandomValueStringGenerator generator = mock(RandomValueStringGenerator.class);
        Mockito.when(generator.generate()).thenReturn("duplicate");
        expiringCodeStore.setGenerator(generator);

        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());
        expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());
    }

    @Test
    public void testRetrieveCode() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());

        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZoneHolder.get().getId());

        Assert.assertEquals(generatedCode, retrievedCode);

        Assert.assertNull(expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZoneHolder.get().getId()));
    }

    @Test
    public void testRetrieveCode_In_Another_Zone() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 60000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());

        IdentityZoneHolder.set(MultitenancyFixture.identityZone("other","other"));
        Assert.assertNull(expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZoneHolder.get().getId()));

        IdentityZoneHolder.clear();
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZoneHolder.get().getId());
        Assert.assertEquals(generatedCode, retrievedCode);


    }

    @Test
    public void testRetrieveCodeWithCodeNotFound() throws Exception {
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode("unknown", IdentityZoneHolder.get().getId());

        Assert.assertNull(retrievedCode);
    }

    @Test(expected = NullPointerException.class)
    public void testRetrieveCodeWithNullCode() throws Exception {
        expiringCodeStore.retrieveCode(null, IdentityZoneHolder.get().getId());
    }

    @Test
    public void testStoreLargeData() throws Exception {
        char[] oneMb = new char[1024 * 1024];
        Arrays.fill(oneMb, 'a');
        String aaaString = new String(oneMb);
        ExpiringCode expiringCode = expiringCodeStore.generateCode(aaaString, new Timestamp(
                        System.currentTimeMillis() + 60000), null, IdentityZoneHolder.get().getId());
        String code = expiringCode.getCode();
        ExpiringCode actualCode = expiringCodeStore.retrieveCode(code, IdentityZoneHolder.get().getId());
        Assert.assertEquals(expiringCode, actualCode);
    }

    @Test
    public void testExpiredCodeReturnsNull() throws Exception {
        long generationTime = 100000L;
        when(timeService.getCurrentTimeMillis()).thenReturn(generationTime);
        String data = "{}";
        Timestamp expiresAt = new Timestamp(generationTime);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());

        long expirationTime = 200000L;
        when(timeService.getCurrentTimeMillis()).thenReturn(expirationTime);
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode(), IdentityZoneHolder.get().getId());
        Assert.assertNull(retrievedCode);
    }

    @Test
    public void testExpireCodeByIntent() throws Exception {
        ExpiringCode code = expiringCodeStore.generateCode("{}", new Timestamp(System.currentTimeMillis() + 60000), "Test Intent", IdentityZoneHolder.get().getId());

        Assert.assertEquals(1, countCodes());

        IdentityZoneHolder.set(MultitenancyFixture.identityZone("id","id"));
        expiringCodeStore.expireByIntent("Test Intent", IdentityZoneHolder.get().getId());
        Assert.assertEquals(1, countCodes());

        IdentityZoneHolder.clear();
        expiringCodeStore.expireByIntent("Test Intent", IdentityZoneHolder.get().getId());
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(code.getCode(), IdentityZoneHolder.get().getId());
        Assert.assertEquals(0, countCodes());
        Assert.assertNull(retrievedCode);
    }

    @Test
    public void testDatabaseDown() throws Exception {
        if (JdbcExpiringCodeStore.class == expiringCodeStoreClass) {
            javax.sql.DataSource ds = mock(javax.sql.DataSource.class);
            Mockito.when(ds.getConnection()).thenThrow(new SQLException());
            ((JdbcExpiringCodeStore) expiringCodeStore).setDataSource(ds);
            try {
                String data = "{}";
                Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 10000000);
                ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt, null, IdentityZoneHolder.get().getId());
                Assert.fail("Database is down, should not generate a code");
            } catch (DataAccessException x) {

            }
        }

    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void testExpirationCleaner() throws Exception {
        when(timeService.getCurrentTimeMillis()).thenReturn(System.currentTimeMillis());
        if (JdbcExpiringCodeStore.class == expiringCodeStoreClass) {
            jdbcTemplate.update(JdbcExpiringCodeStore.insert, "test", System.currentTimeMillis() - 1000, "{}", null, IdentityZoneHolder.get().getId());
            ((JdbcExpiringCodeStore) expiringCodeStore).cleanExpiredEntries();
            jdbcTemplate.queryForObject(JdbcExpiringCodeStore.selectAllFields,
                            new JdbcExpiringCodeStore.JdbcExpiringCodeMapper(), "test", IdentityZoneHolder.get().getId());
        } else {
            throw new EmptyResultDataAccessException(1);
        }

    }
}
