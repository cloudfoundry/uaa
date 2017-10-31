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

package org.cloudfoundry.identity.uaa.db;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.tomcat.jdbc.pool.DataSource;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.mock.env.MockEnvironment;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.cloudfoundry.identity.uaa.db.Vendor.hsqldb;
import static org.cloudfoundry.identity.uaa.db.Vendor.mysql;
import static org.cloudfoundry.identity.uaa.db.Vendor.postgresql;
import static org.cloudfoundry.identity.uaa.db.Vendor.sqlserver;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class DatabaseParametersTests {


    @Parameterized.Parameters(name = "{index}: database[{0}]")
    public static Object[][] parameters() {
        return new Object[][] {{mysql}, {postgresql}, {hsqldb}, {sqlserver}};
    }

    private final Vendor vendor;
    private UrlTester tester;

    public DatabaseParametersTests(Vendor vendor) {
        this.vendor = vendor;
    }

    @Before
    public void setup() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        environment.setProperty("database.initialsize", "0");
        environment.setProperty("database.validationquerytimeout", "5");
        environment.setProperty("database.connecttimeout", "5");
        environment.setActiveProfiles(vendor.name());
        tester = new UrlTester();
        tester.setUp(environment);

    }

    @After
    public void teardown() throws Exception {
        tester.teardown();
    }

    @Test
    public void initial_size() throws Exception {
        assertEquals(0, tester.getDataSource().getInitialSize());
    }

    @Test
    public void validation_query_timeout() throws Exception {
        assertEquals(5, tester.getDataSource().getValidationQueryTimeout());
    }

    @Test
    public void connection_timeout_property_set() throws Exception {
        switch (vendor) {
            case mysql : {
                assertEquals("5000", tester.getUrlParameter("connectTimeout"));
                break;
            }
            case postgresql : {
                assertEquals("5", tester.getUrlParameter("connectTimeout"));
                break;
            }
            case sqlserver : {
                assertEquals("5", tester.getUrlParameter("loginTimeout"));
                break;
            }
            case hsqldb : {break;}
            default : throw new IllegalStateException("Unrecognized database: "+ vendor);
        }

    }

    public static class UrlTester extends JdbcTestBase {
        public void teardown() throws Exception {
            super.tearDown(true);
        }

        @Override
        public void setUp() throws Exception {
            //no op
        }

        @Override
        public void setUp(MockEnvironment environment) throws Exception {
            super.setUp(environment);
        }

        public DataSource getDataSource() {
            return (DataSource)dataSource;
        }

        public String getUrlParameter(String name) throws URISyntaxException {
            String dburl = getDataSource().getUrl();
            URI uri = URI.create("http://localhost" + dburl.substring(dburl.indexOf("?")));
            List<NameValuePair> pairs = URLEncodedUtils.parse(uri, StandardCharsets.UTF_8);
            for (NameValuePair p : pairs) {
                if (name.equals(p.getName())) {
                    return p.getValue();
                }
            }
            return null;
        }
    }

}
