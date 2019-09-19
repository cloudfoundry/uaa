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

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.springframework.mock.env.MockEnvironment;

import java.sql.Connection;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class RevocableTokenIndexTest_4_0_8 extends JdbcTestBase {

    private String springProfile;
    private String tableName;
    private String indexName;
    private boolean unique;

    public RevocableTokenIndexTest_4_0_8(String springProfile, String tableName, String indexName, boolean unique) {
        this.springProfile = springProfile;
        this.tableName = tableName;
        this.indexName = indexName;
        this.unique = unique;
    }

    @Parameterized.Parameters(name = "{index}: org.cloudfoundry.identity.uaa.db[{0}]; table[{1}]; name[{2}]; unique[{3}];")
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
            {null, "revocable_tokens", "revocable_tokens_zone_id", false},
        });
    }

    @Override
    public void setUp() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        if ( springProfile!=null ) {
            environment.setActiveProfiles(springProfile);
        }
        setUp(environment);
    }


    @Test
    public void test_existing_indicies() throws Exception {
        boolean found = false;
        for (String tableName : Arrays.asList(tableName.toLowerCase(), tableName.toUpperCase())) {
            try (
                Connection connection = dataSource.getConnection();
                ResultSet rs = connection.getMetaData().getIndexInfo(connection.getCatalog(), null, tableName, unique, true)
            ) {
                while (!found && rs.next()) {
                    found = indexName.equalsIgnoreCase(rs.getString("INDEX_NAME"));
                }
            }
            if (found) {
                break;
            }
        }

        assertTrue(String.format("Expected to find index %s.%s", tableName, indexName), found);
    }

}
