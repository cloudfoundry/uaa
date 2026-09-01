package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.db.hsqldb.V4_114__DeleteUnconfiguredBootstrapIdentityProviders;
import org.cloudfoundry.identity.uaa.provider.KeystoneIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.flywaydb.core.api.migration.Context;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collections;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class DeleteUnconfiguredBootstrapIdentityProvidersTest {

    private DeleteUnconfiguredBootstrapIdentityProviders migration;
    private Context context;
    private Connection connection;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setup() throws SQLException {
        // Since DeleteUnconfiguredBootstrapIdentityProviders exists, TestUtils no longer
        // seeds login-server/ldap/keystone rows here (see its own comment) - this just gives
        // us a clean uaa zone + admin user baseline. Each test below inserts whatever
        // identity_provider rows it actually needs to exercise.
        TestUtils.cleanAndSeedDb(jdbcTemplate);
        // Flyway's BaseJavaMigration validates the class name (must start with V/R) in its
        // own constructor, so the shared base class can't be instantiated directly - use one
        // of the concrete per-engine subclasses, same as this suite runs against (hsqldb).
        migration = new V4_114__DeleteUnconfiguredBootstrapIdentityProviders();
        connection = jdbcTemplate.getDataSource().getConnection();
        context = mock(Context.class);
        when(context.getConnection()).thenReturn(connection);
    }

    @AfterEach
    void closeConnection() {
        try {
            connection.close();
        } catch (Exception _) {
            // ignore
        }
    }

    @Test
    void deletesTheStillUnconfiguredLoginServerKeystoneAndLdapRows() {
        // Reproduces exactly what V2.0.2 (BootstrapIdentityZones) leaves behind for a
        // never-configured origin: a row with config=null.
        insertProvider(OriginKeys.LOGIN_SERVER, null);
        insertProvider(OriginKeys.KEYSTONE, null);
        insertProvider(OriginKeys.LDAP, null);

        migration.migrate(context);

        assertThat(countOrigin(OriginKeys.LOGIN_SERVER)).isZero();
        assertThat(countOrigin(OriginKeys.KEYSTONE)).isZero();
        assertThat(countOrigin(OriginKeys.LDAP)).isZero();
    }

    @Test
    void neverTouchesTheUaaOrigin() {
        migration.migrate(context);

        assertThat(countOrigin(OriginKeys.UAA)).isEqualTo(1);
    }

    @Test
    void doesNotDeleteAnLdapProviderThatHasRealConnectionDetails() {
        LdapIdentityProviderDefinition realConfig = new LdapIdentityProviderDefinition();
        realConfig.setBaseUrl("ldap://localhost:389/");
        insertProvider(OriginKeys.LDAP, JsonUtils.writeValueAsString(realConfig));

        migration.migrate(context);

        assertThat(countOrigin(OriginKeys.LDAP)).isEqualTo(1);
    }

    @Test
    void doesNotDeleteAKeystoneProviderThatHasRealConfiguration() {
        KeystoneIdentityProviderDefinition realConfig =
                new KeystoneIdentityProviderDefinition(Collections.singletonMap("endpoint", "http://localhost:35357/v2.0"));
        insertProvider(OriginKeys.KEYSTONE, JsonUtils.writeValueAsString(realConfig));

        migration.migrate(context);

        assertThat(countOrigin(OriginKeys.KEYSTONE)).isEqualTo(1);
    }

    @Test
    void deletesAnLdapProviderWithNonNullButStillUnconfiguredContent() {
        // This is what IdentityProviderBootstrap#addLdapProvider() writes when the `ldap`
        // Spring profile is active but no real `ldap:` config was supplied (or it only
        // contains control flags like `override`): a structurally-real but empty
        // LdapIdentityProviderDefinition, not a SQL NULL. The migration has to recognize
        // this as "still unconfigured" too, not just bail out on `config IS NOT NULL`.
        insertProvider(OriginKeys.LDAP, JsonUtils.writeValueAsString(new LdapIdentityProviderDefinition()));

        migration.migrate(context);

        assertThat(countOrigin(OriginKeys.LDAP)).isZero();
    }

    @Test
    void leavesAnUnparseableConfigAlone() {
        insertProvider(OriginKeys.LDAP, "not valid json");

        migration.migrate(context);

        // Can't tell what this row represents, so don't risk deleting it.
        assertThat(countOrigin(OriginKeys.LDAP)).isEqualTo(1);
    }

    private void insertProvider(String origin, String config) {
        jdbcTemplate.update(
                "insert into identity_provider (id, created, lastModified, version, identity_zone_id, name, origin_key, type, config, active) " +
                        "values (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 0, ?, ?, ?, ?, ?, ?)",
                UUID.randomUUID().toString(), IdentityZone.getUaaZoneId(), origin, origin, origin, config, true);
    }

    private int countOrigin(String origin) {
        Integer count = jdbcTemplate.queryForObject(
                "select count(*) from identity_provider where identity_zone_id = ? and origin_key = ?",
                Integer.class, IdentityZone.getUaaZoneId(), origin);
        return count == null ? 0 : count;
    }
}
