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

package org.cloudfoundry.identity.uaa.performance;

import org.cloudfoundry.identity.uaa.rest.SearchResults;
import org.cloudfoundry.identity.uaa.rest.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.scim.endpoints.ScimUserEndpoints;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.jdbc.ScimSearchQueryConverter;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

@RunWith(Parameterized.class)
public class TestMySQLEmailSearch extends JdbcTestBase {


    @BeforeClass
    public static void ignorePerformanceTest() throws Exception {
        //comment out this line to run the tests.
        assumeTrue(false);
    }

    public static final String MYSQL_DEFAULT = "mysql,default";
    public static final String MYSQL_1_INDEX = "CREATE INDEX user_perf_email ON users(email)";
    public static final String MYSQL_2_INDEX = MYSQL_1_INDEX;
    public static final String MYSQL_DROP_INDEX = "DROP INDEX user_perf_email ON users";

    public static final String POSTGRESQL_DEFAULT = "postgresql,default";
    public static final String POSTGRESQL_1_INDEX = "CREATE INDEX user_perf_email ON users(LOWER(email))";
    public static final String  POSTGRESQL_2_INDEX = POSTGRESQL_1_INDEX;
    public static final String POSTGRESQL_DROP_INDEX = "DROP INDEX user_perf_email";

    public static final String HSQLDB_DEFAULT = "hsqldb,default";
    public static final String HSQLDB_1_INDEX = "CREATE INDEX user_perf_email ON users(email)";
    public static final String HSQLDB_2_INDEX = HSQLDB_1_INDEX;
    public static final String HSQLDB_DROP_INDEX = POSTGRESQL_DROP_INDEX;

    public static final String CLEAR_USERS = "delete from users";

    private volatile boolean success = false;

    @Parameters(name = "{index}: profile:{0}")
    public static Collection<Object[]> data() {
        return Arrays.asList(
            new Object[] {MYSQL_DEFAULT, MYSQL_1_INDEX, MYSQL_2_INDEX, MYSQL_DROP_INDEX},
            new Object[] {HSQLDB_DEFAULT, HSQLDB_1_INDEX, HSQLDB_2_INDEX, HSQLDB_DROP_INDEX},
            new Object[] {POSTGRESQL_DEFAULT, POSTGRESQL_1_INDEX, POSTGRESQL_2_INDEX, POSTGRESQL_DROP_INDEX}
        );
    }

    static final int RESULT_COUNT = 100;
    static final int TABLE_SIZE = 100000;

    ScimUserEndpoints endpoint = null;
    private final String profile;
    private final String firstIndex;
    private final String secondIndex;
    private final String dropIndex;

    public TestMySQLEmailSearch(String profile, String firstIndex, String secondIndex, String dropIndex) {
        this.profile = profile;
        this.firstIndex = firstIndex;
        this.secondIndex = secondIndex;
        this.dropIndex = dropIndex;
    }

    @Override
    public void tearDown() throws Exception {
        if (HSQLDB_DEFAULT.equals(profile) || (!success)) {
            super.tearDown();
        }
    }

    @Before
    @Override
    public void setUp() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        environment.setProperty("database.removeabandoned", "false");
        environment.setProperty("database.logabandoned", "false");
        environment.setProperty("spring.profiles.active", profile);
        super.setUp(environment);

        ScimSearchQueryConverter converter = new ScimSearchQueryConverter();
        converter.setDbCaseInsensitive(profile.equals(MYSQL_DEFAULT));

        JdbcScimUserProvisioning userProvisioning = new JdbcScimUserProvisioning(jdbcTemplate, new JdbcPagingListFactory(jdbcTemplate, limitSqlAdapter));
        userProvisioning.setQueryConverter(converter);
        endpoint = new ScimUserEndpoints();
        endpoint.setScimUserProvisioning(userProvisioning);
    }

    protected List<String> addRecords() throws Exception {
        List<String> emails = new LinkedList<>();
        long time = System.currentTimeMillis();
        RandomValueStringGenerator generator = new RandomValueStringGenerator();
        Connection con = dataSource.getConnection();
        PreparedStatement st = con.prepareStatement("insert into users (id, username, email, password, verified) values (?, ?, ?,?, true)");
        boolean doBatch = false;
        for (int i=0; i<TABLE_SIZE; i++) {
            String id = generator.generate()+generator.generate();
            String other = generator.generate() + "@domain-"+generator.generate()+".com";
            int pos = 1;
            st.setString(pos++, id);
            st.setString(pos++, other);
            st.setString(pos++, other);
            st.setString(pos++, other);
            st.addBatch();
            doBatch = true;
            st.clearParameters();
            if (i % (TABLE_SIZE/RESULT_COUNT) == 0) {
                if (emails.size()<RESULT_COUNT) {
                    emails.add(other);
                }
                st.executeBatch();
                System.err.println("Time of execution:" + (System.currentTimeMillis() - time) + " ms. Records:" + i);
                doBatch = false;
            }
        }
        if (doBatch) {
            st.executeBatch();
        }
        st.close();
        con.close();
        return emails;
    }

    protected int countRows() throws Exception {
        return jdbcTemplate.queryForInt("select count(*) from users");
    }

    protected List<String> getEmails() {
        final Random r = new Random(System.currentTimeMillis());
        final List<String> results = new LinkedList<>();
        RowCallbackHandler row = new RowCallbackHandler() {
            @Override
            public void processRow(ResultSet rs) throws SQLException {
                String s = rs.getString(1);
                if (r.nextInt(10) == 1) {
                    results.add(s);
                }
                if (results.size() == RESULT_COUNT) {
                    throw new SQLException("abort");
                }
            }
        };
        while (results.size()<RESULT_COUNT) {
            try {
                jdbcTemplate.query("select email from users", row);
            } catch (Exception x) {
            }
        }
        return results;
    }

    protected String constructQueryFilter(List<String> emails) {
        assertEquals(RESULT_COUNT, emails.size());
        StringBuffer filter = new StringBuffer("(");
        for (String s : emails) {
            if (filter.length()>1) {
                filter.append(" OR ");
            }
            filter.append("email eq \"");
            filter.append(s.toLowerCase()); //ensure we test case insensitivity
            filter.append("\"");
        }
        filter.append(")");
        return filter.toString();
    }

    @Test
    public void simpleTest() throws Exception {
        try {
            jdbcTemplate.update(dropIndex);
        } catch (Exception x) {
            //ignore if it doesn't exist.
        }
        int count = countRows();
        List<String> emails;
        if (count<TABLE_SIZE) {
            jdbcTemplate.update(CLEAR_USERS);
            emails = addRecords();
            assertEquals(TABLE_SIZE, countRows());
        } else {
            emails = getEmails();
        }
        String filter = constructQueryFilter(emails);
        System.err.println("Filter:\n"+filter);
        time100UserFilter(filter);
        time100UserFilter(filter);
        jdbcTemplate.update(firstIndex);
        time100UserFilter(filter);
        time100UserFilter(filter);
        jdbcTemplate.update(dropIndex);
        if (!firstIndex.equals(secondIndex)) {
            jdbcTemplate.update(secondIndex);
            time100UserFilter(filter);
            time100UserFilter(filter);
            jdbcTemplate.update(dropIndex);
        }
        success = true;
    }

    protected void time100UserFilter(String filter) {
        long start = System.currentTimeMillis();
        SearchResults<?> results = endpoint.findUsers("id,userName,emails", filter.toString(), null, "ascending", 1, RESULT_COUNT);
        assertEquals(RESULT_COUNT, results.getTotalResults());
        long stop = System.currentTimeMillis();
        System.err.println("Time to query:"+(stop-start)+" ms.");
    }

}
