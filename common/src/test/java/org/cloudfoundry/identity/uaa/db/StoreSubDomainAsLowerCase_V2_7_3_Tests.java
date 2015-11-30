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

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

public class StoreSubDomainAsLowerCase_V2_7_3_Tests extends JdbcTestBase {

    private IdentityZoneProvisioning provisioning;
    private StoreSubDomainAsLowerCase_V2_7_3 migration;
    private RandomValueStringGenerator generator;

    @Before
    public void setUpDuplicateZones() {
        provisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        migration = new StoreSubDomainAsLowerCase_V2_7_3();
        generator = new RandomValueStringGenerator(6);
    }

    @Test
    public void ensure_that_subdomains_get_lower_cased() throws Exception {
        List<String> subdomains = Arrays.asList(
            "Zone1" + generator.generate(),
            "Zone2" + generator.generate(),
            "Zone3" + generator.generate(),
            "Zone4+generator.generate()"
        );

        for (String subdomain : subdomains) {
            IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
            IdentityZone created = provisioning.create(zone);
            assertEquals(subdomain.toLowerCase(), created.getSubdomain());
            jdbcTemplate.update("UPDATE identity_zone SET subdomain = ? WHERE id = ?", subdomain, subdomain);
            assertEquals(subdomain, jdbcTemplate.queryForObject("SELECT subdomain FROM identity_zone where id = ?", String.class, subdomain));
        }

        migration.migrate(jdbcTemplate);
        for (String subdomain : subdomains) {
            for (IdentityZone zone :
                Arrays.asList(
                    provisioning.retrieve(subdomain),
                    provisioning.retrieveBySubdomain(subdomain.toLowerCase()),
                    provisioning.retrieveBySubdomain(subdomain)
                )
                ) {
                assertNotNull(zone);
                assertEquals(subdomain, zone.getId());
                assertEquals(subdomain.toLowerCase(), zone.getSubdomain());
            }
        }
    }

    @Test
    public void test_duplicate_subdomains() throws Exception {
        check_db_is_case_sensitive();
        List<String> ids = Arrays.asList(
            "id1"+generator.generate().toLowerCase(),
            "id2"+generator.generate().toLowerCase(),
            "id3"+generator.generate().toLowerCase(),
            "id4"+generator.generate().toLowerCase(),
            "id5"+generator.generate().toLowerCase()
        );
        List<String> subdomains = Arrays.asList(
            "domain1",
            "Domain1",
            "doMain1",
            "domain4"+generator.generate().toLowerCase(),
            "domain5"+generator.generate().toLowerCase()
        );
        for (int i=0; i<ids.size(); i++) {
            IdentityZone zone = MultitenancyFixture.identityZone(ids.get(i), subdomains.get(i));
            zone.setSubdomain(subdomains.get(i)); //mixed case
            createIdentityZoneThroughSQL(zone);
        }
        IdentityZone lowercase = provisioning.retrieveBySubdomain("domain1");
        IdentityZone mixedcase = provisioning.retrieveBySubdomain("Domain1");
        assertEquals(lowercase.getId(), mixedcase.getId());

        migration.migrate(jdbcTemplate);

        for (IdentityZone zone : provisioning.retrieveAll()) {
            //ensure we converted to lower case
            assertEquals(zone.getSubdomain().toLowerCase(), zone.getSubdomain());
        }
     }


    public void check_db_is_case_sensitive() throws Exception {
        String usubdomain = "TEST_UPPER_" + generator.generate();
        String lsubdomain = usubdomain.toLowerCase();

        //check if the DB is case sensitive
        for (String subdomain : Arrays.asList(usubdomain, lsubdomain)) {
            try {
                IdentityZone identityZone = MultitenancyFixture.identityZone(subdomain+generator.generate(), subdomain);
                identityZone.setSubdomain(subdomain);
                createIdentityZoneThroughSQL(identityZone);
            } catch (SQLException x) {
                assumeTrue("DB is not case sensitive. No need for this test", false);
            } catch (DuplicateKeyException x) {
                assumeTrue("DB is not case sensitive. No need for this test", false);
            }
        }
    }

    protected void createIdentityZoneThroughSQL(IdentityZone identityZone) throws SQLException {
        String ID_ZONE_FIELDS = "id,version,created,lastmodified,name,subdomain,description";
        String CREATE_IDENTITY_ZONE_SQL = "insert into identity_zone(" + ID_ZONE_FIELDS + ") values (?,?,?,?,?,?,?)";

        jdbcTemplate.update(CREATE_IDENTITY_ZONE_SQL, ps -> {
            ps.setString(1, identityZone.getId().trim());
            ps.setInt(2, identityZone.getVersion());
            ps.setTimestamp(3, new Timestamp(new Date().getTime()));
            ps.setTimestamp(4, new Timestamp(new Date().getTime()));
            ps.setString(5, identityZone.getName());
            ps.setString(6, identityZone.getSubdomain());
            ps.setString(7, identityZone.getDescription());
        });
    }
}