package org.cloudfoundry.identity.uaa.db;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.KeystoneIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * V2.0.2 ({@link BootstrapIdentityZones}) unconditionally inserted a placeholder
 * {@code identity_provider} row for each of "uaa", "login-server", "ldap", and
 * "keystone" in the {@code uaa} zone, with {@code config = null} - regardless
 * of whether anything was ever actually configured for those origins. That
 * row's mere existence blocks provisioning a real identity provider for that
 * origin via {@code POST /identity-providers} (unique
 * {@code (identity_zone_id, origin_key)} index), and serves no operational
 * purpose if nothing has ever configured it.
 * <p>
 * This migration removes exactly those rows that are STILL in that
 * never-configured state. It never touches a row that has ever had real
 * configuration applied to it - whether by {@code IdentityProviderBootstrap},
 * the REST API, or by hand. "ldap" and "keystone" rows can carry a non-null
 * but still-empty JSON config (bootstrap code overwrites the literal
 * {@code NULL} with an unconfigured definition on every boot), so this checks
 * the parsed content, not just {@code config IS NULL}.
 * <p>
 * "uaa" is never touched: it's the mandatory internal auth source and is kept
 * actively managed by {@code IdentityProviderBootstrap#updateDefaultZoneUaaIDP}.
 * "login-server" has no bootstrap code that ever populates its config, so a
 * plain {@code NULL} check is sufficient there.
 */
public class DeleteUnconfiguredBootstrapIdentityProviders extends BaseJavaMigration {

    @Override
    public void migrate(Context context) {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(new SingleConnectionDataSource(context.getConnection(), true));
        String uaaZoneId = IdentityZone.getUaaZoneId();

        deleteIfConfigIsNull(jdbcTemplate, uaaZoneId, OriginKeys.LOGIN_SERVER);
        deleteIfUnconfigured(jdbcTemplate, uaaZoneId, OriginKeys.KEYSTONE,
                DeleteUnconfiguredBootstrapIdentityProviders::keystoneIsUnconfigured);
        deleteIfUnconfigured(jdbcTemplate, uaaZoneId, OriginKeys.LDAP,
                DeleteUnconfiguredBootstrapIdentityProviders::ldapIsUnconfigured);
    }

    private void deleteIfConfigIsNull(JdbcTemplate jdbcTemplate, String zoneId, String origin) {
        jdbcTemplate.update(
                "delete from identity_provider where identity_zone_id = ? and origin_key = ? and config is null",
                zoneId, origin);
    }

    private void deleteIfUnconfigured(JdbcTemplate jdbcTemplate, String zoneId, String origin,
            Predicate<String> isUnconfigured) {
        List<Map<String, Object>> rows = jdbcTemplate.queryForList(
                "select id, config from identity_provider where identity_zone_id = ? and origin_key = ?",
                zoneId, origin);
        for (Map<String, Object> row : rows) {
            String config = (String) row.get("config");
            if (config == null || isUnconfigured.test(config)) {
                jdbcTemplate.update("delete from identity_provider where id = ?", row.get("id"));
            }
        }
    }

    private static boolean ldapIsUnconfigured(String config) {
        try {
            LdapIdentityProviderDefinition definition = JsonUtils.readValue(config, LdapIdentityProviderDefinition.class);
            return definition == null || !definition.isConfigured();
        } catch (JsonUtils.JsonUtilException e) {
            // Not parseable as an LDAP definition - leave it alone rather than risk deleting
            // something we don't understand.
            return false;
        }
    }

    private static boolean keystoneIsUnconfigured(String config) {
        try {
            KeystoneIdentityProviderDefinition definition = JsonUtils.readValue(config, KeystoneIdentityProviderDefinition.class);
            return definition == null
                    || definition.getAdditionalConfiguration() == null
                    || definition.getAdditionalConfiguration().isEmpty();
        } catch (JsonUtils.JsonUtilException e) {
            return false;
        }
    }
}
