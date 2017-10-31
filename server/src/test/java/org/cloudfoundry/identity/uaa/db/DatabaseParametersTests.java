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
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class DatabaseParametersTests extends JdbcTestBase {


    private Vendor vendor;

    @Override
    @Before
    public void setUp() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        environment.setProperty("database.initialsize", "0");
        environment.setProperty("database.validationquerytimeout", "5");
        environment.setProperty("database.connecttimeout", "5");
        if (System.getProperty("spring.profiles.active")!=null) {
            environment.setActiveProfiles(StringUtils.commaDelimitedListToStringArray(System.getProperty("spring.profiles.active")));
        }
        super.setUp(environment);
        vendor = webApplicationContext.getBean(DatabaseUrlModifier.class).getDatabaseType();
    }

    @Test
    public void initial_size() throws Exception {
        assertEquals(0, getDataSource().getInitialSize());
    }

    @Test
    public void validation_query_timeout() throws Exception {
        assertEquals(5, getDataSource().getValidationQueryTimeout());
    }

    @Test
    public void connection_timeout_property_set() throws Exception {
        switch (vendor) {
            case mysql : {
                assertEquals("5000", getUrlParameter("connectTimeout"));
                break;
            }
            case postgresql : {
                assertEquals("5", getUrlParameter("connectTimeout"));
                break;
            }
            case sqlserver : {
                assertEquals("5", getUrlParameter("loginTimeout"));
                break;
            }
            case hsqldb : {break;}
            default : throw new IllegalStateException("Unrecognized database: "+ vendor);
        }

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
