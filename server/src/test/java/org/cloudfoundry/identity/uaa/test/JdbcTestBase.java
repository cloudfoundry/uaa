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
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapter;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.flywaydb.core.Flyway;
import org.junit.After;
import org.junit.Before;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

import javax.sql.DataSource;
import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.KEYSTONE;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;

public class JdbcTestBase extends TestClassNullifier {

    protected XmlWebApplicationContext webApplicationContext;
    protected Flyway flyway;
    protected JdbcTemplate jdbcTemplate;
    protected DataSource dataSource;
    protected LimitSqlAdapter limitSqlAdapter;
    protected MockEnvironment environment;
    protected String validationQuery;

    @Before
    public void setUp() throws Exception {
        IdentityZoneHolder.clear();
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
        validationQuery = webApplicationContext.getBean("validationQuery", String.class);
    }

    public void cleanData() {
        IdentityZoneHolder.clear();
        //flyway.clean();
        jdbcTemplate.update("DELETE FROM authz_approvals");
        jdbcTemplate.update("DELETE FROM expiring_code_store");
        jdbcTemplate.update("DELETE FROM external_group_mapping");
        jdbcTemplate.update("DELETE FROM group_membership");
        jdbcTemplate.update("DELETE FROM groups");
        jdbcTemplate.update("DELETE FROM identity_provider");
        jdbcTemplate.update("DELETE FROM identity_zone");
        jdbcTemplate.update("DELETE FROM oauth_client_details");
        jdbcTemplate.update("DELETE FROM oauth_code");
        jdbcTemplate.update("DELETE FROM revocable_tokens");
        jdbcTemplate.update("DELETE FROM sec_audit");
        jdbcTemplate.update("DELETE FROM service_provider");
        jdbcTemplate.update("DELETE FROM user_info");
        jdbcTemplate.update("DELETE FROM users");

        //this is data that the migration scripts insert
        jdbcTemplate.update("INSERT INTO identity_zone (id,version,subdomain,name,description,config) VALUES ('uaa',0,'','uaa','The system zone for backwards compatibility',null)");

        JdbcIdentityProviderProvisioning idp = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        for (String origin : Arrays.asList(UAA,LDAP, LOGIN_SERVER, KEYSTONE)) {
            IdentityProvider provider = new IdentityProvider()
                .setOriginKey(origin)
                .setActive(true)
                .setIdentityZoneId(IdentityZone.getUaa().getId())
                .setName(origin)
                .setType(origin);
            idp.create(provider);
        }

    }

    @After
    public void tearDown() throws Exception {
        tearDown(true);
    }

    public final void tearDown(boolean cleandata) throws Exception {
        if (cleandata) {
            cleanData();
        }
        IdentityZoneHolder.clear();
        ((org.apache.tomcat.jdbc.pool.DataSource)dataSource).close(true);
        webApplicationContext.destroy();
    }
}
