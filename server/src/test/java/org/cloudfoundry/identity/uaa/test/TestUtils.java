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

import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.jdbc.datasource.init.ScriptStatementFailedException;
import org.springframework.util.ClassUtils;

import javax.sql.DataSource;
import java.sql.Connection;
import java.util.Arrays;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.KEYSTONE;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LOGIN_SERVER;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

/**
 * Common methods for DB manipulation and so on.
 *
 *
 */
public class TestUtils {

    private static Environment environment = TestProfileEnvironment.getEnvironment();

    private static String platform = environment.acceptsProfiles("postgresql") ? "postgresql" : "hsqldb";

    public static void cleanTestDatabaseData(JdbcTemplate jdbcTemplate) {
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
        for (String origin : Arrays.asList(UAA, LDAP, LOGIN_SERVER, KEYSTONE)) {
            IdentityProvider provider = new IdentityProvider()
                .setOriginKey(origin)
                .setActive(true)
                .setIdentityZoneId(IdentityZone.getUaa().getId())
                .setName(origin)
                .setType(origin);
            idp.create(provider);
        }
    }


    public static void runScript(DataSource dataSource, String stem) throws Exception {
        ResourceDatabasePopulator populator = new ResourceDatabasePopulator();
        String packageName = ClassUtils.getPackageName(TestUtils.class).replace(".", "/");
        populator.addScript(new ClassPathResource(packageName.substring(0, packageName.lastIndexOf("/")) + "/" + stem
                        + "-" + platform + ".sql"));
        Connection connection = dataSource.getConnection();
        try {
            populator.populate(connection);
        } catch (ScriptStatementFailedException e) {
            // ignore
        } finally {
            DataSourceUtils.releaseConnection(connection, dataSource);
        }
    }

    public static void createSchema(DataSource dataSource) throws Exception {
        runScript(dataSource, "schema");
    }

    public static void dropSchema(DataSource dataSource) throws Exception {
        runScript(dataSource, "schema-drop");
    }

    public static void deleteFrom(DataSource dataSource, String... tables) throws Exception {
        for (String table : tables) {
            new JdbcTemplate(dataSource).update("delete from " + table);
        }
    }

    public static void assertNoSuchUser(JdbcTemplate template, String column, String value) {
        assertThat(template.queryForObject("select count(id) from users where " + column + "='" + value + "'", Integer.class), is(0));
    }

}
