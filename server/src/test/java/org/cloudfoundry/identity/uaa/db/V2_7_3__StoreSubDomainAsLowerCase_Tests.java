package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class V2_7_3__StoreSubDomainAsLowerCase_Tests {

    private IdentityZoneProvisioning provisioning;
    private V2_7_3__StoreSubDomainAsLowerCase migration;
    private RandomValueStringGenerator generator;
    private Context context;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private Connection connection;

    @AfterEach
    void closeConnection() {
        try {
            connection.close();
        } catch (Exception ignore) {
            // ignore
        }
    }

    @BeforeEach
    void setUpDuplicateZones() throws SQLException {
        provisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        migration = new V2_7_3__StoreSubDomainAsLowerCase();
        generator = new RandomValueStringGenerator(6);
        connection = jdbcTemplate.getDataSource().getConnection();
        context = mock(Context.class);
        when(context.getConnection()).thenReturn(connection);
    }

    @Test
    void ensureThatSubdomainsGetLowerCased() {
        List<String> subdomains = Arrays.asList(
                "Zone1" + generator.generate(),
                "Zone2" + generator.generate(),
                "Zone3" + generator.generate(),
                "Zone4+generator.generate()"
        );

        for (String subdomain : subdomains) {
            IdentityZone zone = MultitenancyFixture.identityZone(subdomain, subdomain);
            IdentityZone created = provisioning.create(zone);
            assertThat(created.getSubdomain()).isEqualTo(subdomain.toLowerCase());
            jdbcTemplate.update("UPDATE identity_zone SET subdomain = ? WHERE id = ?", subdomain, subdomain);
            assertThat(jdbcTemplate.queryForObject("SELECT subdomain FROM identity_zone where id = ?", String.class, subdomain)).isEqualTo(subdomain);
        }

        migration.migrate(context);
        for (String subdomain : subdomains) {
            for (IdentityZone zone :
                    Arrays.asList(
                            provisioning.retrieve(subdomain),
                            provisioning.retrieveBySubdomain(subdomain.toLowerCase()),
                            provisioning.retrieveBySubdomain(subdomain)
                    )
            ) {
                assertThat(zone).isNotNull();
                assertThat(zone.getId()).isEqualTo(subdomain);
                assertThat(zone.getSubdomain()).isEqualTo(subdomain.toLowerCase());
            }
        }
    }

    @Test
    void duplicateSubdomains() {
        checkDbIsCaseSensitive();
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
        for (int i = 0; i < ids.size(); i++) {
            IdentityZone zone = MultitenancyFixture.identityZone(ids.get(i), subdomains.get(i));
            zone.setSubdomain(subdomains.get(i)); //mixed case
            createIdentityZoneThroughSQL(zone);
        }
        IdentityZone lowercase = provisioning.retrieveBySubdomain("domain1");
        IdentityZone mixedcase = provisioning.retrieveBySubdomain("Domain1");
        assertThat(mixedcase.getId()).isEqualTo(lowercase.getId());

        migration.migrate(context);

        for (IdentityZone zone : provisioning.retrieveAll()) {
            //ensure we converted to lower case
            assertThat(zone.getSubdomain()).isEqualTo(zone.getSubdomain().toLowerCase());
        }
    }

    public void checkDbIsCaseSensitive() {
        String usubdomain = "TEST_UPPER_" + generator.generate();
        String lsubdomain = usubdomain.toLowerCase();

        //check if the DB is case sensitive
        for (String subdomain : Arrays.asList(usubdomain, lsubdomain)) {
            try {
                IdentityZone identityZone = MultitenancyFixture.identityZone(subdomain + generator.generate(), subdomain);
                identityZone.setSubdomain(subdomain);
                createIdentityZoneThroughSQL(identityZone);
            } catch (DuplicateKeyException x) {
                assumeTrue(false, "DB is not case sensitive. No need for this test");
            }
        }
    }

    protected void createIdentityZoneThroughSQL(IdentityZone identityZone) {
        String idZoneFields = "id,version,created,lastmodified,name,subdomain,description";
        String createIdentityZoneSql = "insert into identity_zone(" + idZoneFields + ") values (?,?,?,?,?,?,?)";

        jdbcTemplate.update(createIdentityZoneSql, ps -> {
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