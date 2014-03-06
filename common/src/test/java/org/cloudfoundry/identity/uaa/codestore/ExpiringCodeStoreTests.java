package org.cloudfoundry.identity.uaa.codestore;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;

import javax.activation.DataSource;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.codestore.JdbcExpiringCodeStore.JdbcExpiringCodeMapper;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestContextManager;
import org.springframework.util.ReflectionUtils;

@ContextConfiguration(locations = {"classpath:spring/env.xml", "classpath:spring/data-source.xml"})
@RunWith(Parameterized.class)
@IfProfileValue(name = "spring.profiles.active", values = {"", "test,postgresql", "hsqldb", "test,mysql", "test,oracle"})
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class ExpiringCodeStoreTests {

    private ExpiringCodeStore expiringCodeStore;
    private Class expiringCodeStoreClass;

    Log logger = LogFactory.getLog(getClass());

    public ExpiringCodeStoreTests(Class expiringCodeStoreClass) {
        this.expiringCodeStoreClass = expiringCodeStoreClass;
    }

    @Parameters
    public static Collection<Object []> data() {
        return Arrays.asList(new Object[][]{
            {InMemoryExpiringCodeStore.class},{JdbcExpiringCodeStore.class},
        });
    }

    
    @Autowired
    JdbcTemplate jdbcTemplate;

    @Before
    public void setUp() throws Exception {
        expiringCodeStore = (ExpiringCodeStore) expiringCodeStoreClass.newInstance();

        TestContextManager testContextManager = new TestContextManager(getClass());
        testContextManager.prepareTestInstance(this);
        
        if (expiringCodeStore instanceof InMemoryExpiringCodeStore) {

        } else {
            //confirm that everything is clean prior to test.
            TestUtils.deleteFrom(jdbcTemplate.getDataSource(), JdbcExpiringCodeStore.tableName);
            if (expiringCodeStore instanceof JdbcExpiringCodeStore) {
                ((JdbcExpiringCodeStore)expiringCodeStore).setDataSource(jdbcTemplate.getDataSource());
            }
        }
    }

    @After
    public void cleanUp() throws Exception {
        Method m = ReflectionUtils.findMethod(jdbcTemplate.getDataSource().getClass(), "close");
        if (m != null) {
            ReflectionUtils.invokeMethod(m, jdbcTemplate.getDataSource());
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
        char[] oneMb = new char[1024*1024];
        Arrays.fill(oneMb, 'a');
        String aaaString = new String(oneMb);
        ExpiringCode expiringCode = expiringCodeStore.generateCode(aaaString, new Timestamp(System.currentTimeMillis()+60000));
        String code = expiringCode.getCode();
        ExpiringCode actualCode = expiringCodeStore.retrieveCode(code);
        assertEquals(expiringCode, actualCode);
    }
    
    @Test
    public void testExpiredCodeReturnsNull() throws Exception {
        String data = "{}";
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 1000);
        ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt);
        Thread.currentThread().sleep(1001);
        ExpiringCode retrievedCode = expiringCodeStore.retrieveCode(generatedCode.getCode());
        assertNull(retrievedCode);
    }
    
    @Test
    public void testDatabaseDown() throws Exception {
        if (JdbcExpiringCodeStore.class == expiringCodeStoreClass) {
            javax.sql.DataSource ds = mock(javax.sql.DataSource.class);
            when(ds.getConnection()).thenThrow(new SQLException());
            ((JdbcExpiringCodeStore)expiringCodeStore).setDataSource(ds);
            try {
                String data = "{}";
                Timestamp expiresAt = new Timestamp(System.currentTimeMillis() + 10000000);
                ExpiringCode generatedCode = expiringCodeStore.generateCode(data, expiresAt);
                fail("Database is down, should not generate a code");
            } catch (DataAccessException x) {
                
            }
        }
        
    }
    
    @Test(expected=EmptyResultDataAccessException.class)
    public void testExpirationCleaner() throws Exception {
        if (JdbcExpiringCodeStore.class == expiringCodeStoreClass) {
            jdbcTemplate.update(JdbcExpiringCodeStore.insert,"test", System.currentTimeMillis()-1000, "{}");
            ((JdbcExpiringCodeStore)expiringCodeStore).cleanExpiredEntries();
            jdbcTemplate.queryForObject(JdbcExpiringCodeStore.select, new JdbcExpiringCodeStore.JdbcExpiringCodeMapper(), "test");
        } else {
            throw new EmptyResultDataAccessException(1);
        }
        
    }
}
