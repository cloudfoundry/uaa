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

package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

public class StoreSubDomainAsLowerCase_V2_7_3_Tests extends DbMigrationIntegrationTestParent {

    @Override
    protected String onlyRunTestsForActiveSpringProfileName() {
        return "";
    }

    private IdentityZoneProvisioning provisioning;
    private RandomValueStringGenerator generator;

    @Before
    public void setUpDuplicateZones() {
        provisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        generator = new RandomValueStringGenerator(6);
    }

    @Test
    public void ensure_that_subdomains_get_lower_cased() {
        List<String> subdomains = Arrays.asList(
                "Zone1" + generator.generate(),
                "Zone2" + generator.generate(),
                "Zone3" + generator.generate(),
                "Zone4+generator.generate()"
        );

        MigrationTest migrationTest = new MigrationTest() {
            @Override
            public String getTargetMigration() { return "2.7.3"; }

            @Override
            public void beforeMigration() {
                for (String subdomain : subdomains) {
                    createIdentityZone(subdomain, subdomain);
                    assertEquals(subdomain, jdbcTemplate.queryForObject("SELECT subdomain FROM identity_zone where id = ?", String.class, subdomain));
                }
            }

            @Override
            public void runAssertions() throws Exception {
                for (String subdomain : subdomains) {
                    assertEquals(subdomain, jdbcTemplate.queryForObject("SELECT id FROM identity_zone where id = ?", String.class, subdomain));
                    assertEquals(subdomain.toLowerCase(), jdbcTemplate.queryForObject("SELECT subdomain FROM identity_zone where id = ?", String.class, subdomain));
                }
            }
        };

        migrationTestRunner.run(migrationTest);
    }

    @Test
    public void test_duplicate_subdomains() throws Exception {
        List<String> ids = Arrays.asList(
                "id1" + generator.generate().toLowerCase(),
                "id2" + generator.generate().toLowerCase(),
                "id3" + generator.generate().toLowerCase(),
                "id4" + generator.generate().toLowerCase(),
                "id5" + generator.generate().toLowerCase()
        );
        List<String> subdomains = Arrays.asList(
                "domain1",
                "Domain1",
                "doMain1",
                "domain4" + generator.generate().toLowerCase(),
                "domain5" + generator.generate().toLowerCase()
        );

        MigrationTest migrationTest = new MigrationTest() {
            @Override
            public String getTargetMigration() { return "2.7.3"; }

            @Override
            public void beforeMigration() {
                check_db_is_case_sensitive();
                for (int i = 0; i < ids.size(); i++) {
                    createIdentityZone(ids.get(i), subdomains.get(i));
                }
                assertEquals("3", jdbcTemplate.queryForObject("SELECT count(*) FROM identity_zone where LOWER(subdomain) = ?", String.class, "domain1"));
            }

            @Override
            public void runAssertions() throws Exception {
                assertEquals("1", jdbcTemplate.queryForObject("SELECT count(*) FROM identity_zone where LOWER(subdomain) = ?", String.class, "domain1"));
            }
        };

        migrationTestRunner.run(migrationTest);
    }


    public void check_db_is_case_sensitive() {
        String usubdomain = "TEST_UPPER_" + generator.generate();
        String lsubdomain = usubdomain.toLowerCase();

        //check if the DB is case sensitive
        for (String subdomain : Arrays.asList(usubdomain, lsubdomain)) {
            try {
                createIdentityZone(subdomain, subdomain);
            } catch (DuplicateKeyException x) {
                assumeTrue("DB is not case sensitive. No need for this test", false);
            }
        }
    }

    protected void createIdentityZone(String id, String identityZone) {
        String sql = "insert into identity_zone(id,version,name,subdomain) values (?,0,'name',?)";
        jdbcTemplate.update(sql, ps -> {
            ps.setString(1, id);
            ps.setString(2, identityZone);
        });
    }
}