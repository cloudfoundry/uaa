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
package org.cloudfoundry.identity.uaa.scim.test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;

import java.sql.Connection;
import java.util.Arrays;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.TestProfileEnvironment;
import org.springframework.core.env.Environment;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.jdbc.datasource.init.ScriptStatementFailedException;
import org.springframework.util.ClassUtils;

/**
 * Common methods for DB manipulation and so on.
 * 
 * @author Luke Taylor
 * @author Dave Syer
 * 
 */
public class TestUtils {

    private static Environment environment = TestProfileEnvironment.getEnvironment();

    private static String platform;

    static {
        try {
            platform = environment.acceptsProfiles("postgresql") ? "postgresql" : "hsqldb";
        } catch (IllegalArgumentException e) {
            // SPRING_PROFILES_ACTIVE not set
            platform = "hsqldb";
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

    public static ScimUser scimUserInstance(String email) {
        ScimUser user = new ScimUser("", email, email, email);
        ScimUser.Email em = new ScimUser.Email();
        em.setValue(email);
        user.setEmails(Arrays.asList(em));
        return user;
    }

}
