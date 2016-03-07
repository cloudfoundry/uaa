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
package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.TestClassNullifier;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.flywaydb.core.Flyway;
import org.junit.After;
import org.junit.Before;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

import javax.sql.DataSource;

public class JdbcTestBase extends TestClassNullifier {

    protected XmlWebApplicationContext webApplicationContext;
    protected Flyway flyway;
    protected JdbcTemplate jdbcTemplate;
    protected DataSource dataSource;
    protected LimitSqlAdapter limitSqlAdapter;
    protected MockEnvironment environment;

    @Before
    public void setUp() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        if (System.getProperty("spring.profiles.active")!=null) {
            environment.setActiveProfiles(StringUtils.commaDelimitedListToStringArray(System.getProperty("spring.profiles.active")));
        }
        setUp(environment);
    }

    public void setUp(MockEnvironment environment) throws Exception {
        this.environment = environment;
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setEnvironment(environment);
        webApplicationContext.setConfigLocations(new String[]{"classpath:spring/env.xml", "classpath:spring/data-source.xml"});
        webApplicationContext.refresh();
        flyway = webApplicationContext.getBean(Flyway.class);
        jdbcTemplate = webApplicationContext.getBean(JdbcTemplate.class);
        dataSource = webApplicationContext.getBean(DataSource.class);
        limitSqlAdapter = webApplicationContext.getBean(LimitSqlAdapter.class);
    }

    @After
    public void tearDown() throws Exception {
        flyway.clean();
        ((org.apache.tomcat.jdbc.pool.DataSource)dataSource).close(true);
        webApplicationContext.destroy();
    }
}
