package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.client.ClientAdminBootstrap;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.IdentityProviderBootstrap;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderData;
import org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactory;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimExternalGroupBootstrap;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimGroupBootstrap;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimUserBootstrap;
import org.cloudfoundry.identity.uaa.util.beans.DbUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;

import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

public class TestUtils {

    public static IdentityZone withId(String id) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        return identityZone;
    }

    public static IdentityZone withSubdomain(String subdomain) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubdomain(subdomain);
        return identityZone;
    }

    public static void restoreToDefaults(ApplicationContext applicationContext) throws SQLException {
        cleanAndSeedDb(applicationContext);
        resetIdentityZoneHolder(applicationContext);
        SecurityContextHolder.clearContext();
    }

    public static void cleanAndSeedDb(JdbcTemplate jdbcTemplate) throws SQLException {
        jdbcTemplate.update("DELETE FROM authz_approvals");
        jdbcTemplate.update("DELETE FROM expiring_code_store");
        jdbcTemplate.update("DELETE FROM external_group_mapping");
        jdbcTemplate.update("DELETE FROM group_membership");
        jdbcTemplate.update("DELETE FROM " +
                new DbUtils().getQuotedIdentifier("groups", jdbcTemplate));
        jdbcTemplate.update("DELETE FROM identity_provider");
        jdbcTemplate.update("DELETE FROM identity_zone");
        jdbcTemplate.update("DELETE FROM oauth_client_details");
        jdbcTemplate.update("DELETE FROM oauth_code");
        jdbcTemplate.update("DELETE FROM revocable_tokens");
        jdbcTemplate.update("DELETE FROM sec_audit");
        jdbcTemplate.update("DELETE FROM user_info");
        jdbcTemplate.update("DELETE FROM users");

        seedUaaZoneSimilarToHowTheRealFlywayMigrationDoesIt(jdbcTemplate);
    }

    private static void cleanAndSeedDb(ApplicationContext applicationContext) throws SQLException {
        if (applicationContext == null) {
            return;
        }

        JdbcTemplate jdbcTemplate;
        try {
            jdbcTemplate = applicationContext.getBean(JdbcTemplate.class);
        } catch (NoSuchBeanDefinitionException ignored) {
            return;
        }

        cleanAndSeedDb(jdbcTemplate);

        bootstrapDb(applicationContext);
    }

    private static void seedUaaZoneSimilarToHowTheRealFlywayMigrationDoesIt(JdbcTemplate jdbcTemplate) {
        IdentityZone uaa = IdentityZone.getUaa();
        Timestamp t = new Timestamp(uaa.getCreated().getTime());
        jdbcTemplate.update("insert into identity_zone VALUES (?,?,?,?,?,?,?,?,?)", uaa.getId(), t, t, uaa.getVersion(), uaa.getSubdomain(), uaa.getName(), uaa.getDescription(), null, true);
        Map<String, String> originMap = new HashMap<>();
        Set<String> origins = new LinkedHashSet<>();
        origins.addAll(Arrays.asList(new String[]{OriginKeys.UAA, OriginKeys.LOGIN_SERVER, OriginKeys.LDAP, OriginKeys.KEYSTONE}));
        origins.addAll(jdbcTemplate.queryForList("SELECT DISTINCT origin from users", String.class));
        for (String origin : origins) {
            String identityProviderId = UUID.randomUUID().toString();
            originMap.put(origin, identityProviderId);
            jdbcTemplate.update("insert into identity_provider VALUES (?,?,?,0,?,?,?,?,null,?,null,null,null)", identityProviderId, t, t, uaa.getId(), origin, origin, origin, true);
        }
        jdbcTemplate.update("update oauth_client_details set identity_zone_id = ?", uaa.getId());
        List<String> clientIds = jdbcTemplate.queryForList("SELECT client_id from oauth_client_details", String.class);
        for (String clientId : clientIds) {
            jdbcTemplate.update("insert into client_idp values (?,?) ", clientId, originMap.get(OriginKeys.UAA));
        }
    }

    private static void bootstrapDb(ApplicationContext applicationContext) {
        tryCallAfterPropertiesSet(applicationContext, IdentityZoneConfigurationBootstrap.class);
        tryCallAfterPropertiesSet(applicationContext, ScimExternalGroupBootstrap.class);
        tryCallAfterPropertiesSet(applicationContext, BootstrapSamlIdentityProviderData.class);
        tryCallAfterPropertiesSet(applicationContext, IdentityProviderBootstrap.class);
        tryCallAfterPropertiesSet(applicationContext, ScimGroupBootstrap.class);
        tryCallAfterPropertiesSet(applicationContext, ScimUserBootstrap.class);

        try {
            ClientAdminBootstrap bootstrap = applicationContext.getBean(ClientAdminBootstrap.class);
            bootstrap.afterPropertiesSet();
        } catch (Exception ignored) {

        }
    }

    private static <T extends InitializingBean> void tryCallAfterPropertiesSet(ApplicationContext applicationContext, Class<T> clazz) {
        try {
            InitializingBean bootstrap = applicationContext.getBean(clazz);
            bootstrap.afterPropertiesSet();
        } catch (Exception ignored) {

        }
    }

    public static void resetIdentityZoneHolder(ApplicationContext applicationContext) {
        IdentityZoneHolder.clear();

        if (applicationContext == null) {
            IdentityZoneHolder.setProvisioning(null);
            IdentityZoneHolder.setSamlKeyManagerFactory(null);
            return;
        }

        try {
            IdentityZoneHolder.setProvisioning(applicationContext.getBean(JdbcIdentityZoneProvisioning.class));
            IdentityZoneHolder.setSamlKeyManagerFactory(applicationContext.getBean(SamlKeyManagerFactory.class));
        } catch (NoSuchBeanDefinitionException ignored) {
            try {
                IdentityZoneHolder.setProvisioning(new JdbcIdentityZoneProvisioning(applicationContext.getBean(JdbcTemplate.class)));
            } catch (NoSuchBeanDefinitionException ignoredAgain) {
                IdentityZoneHolder.setProvisioning(null);
            }
        }
    }

    public static void deleteFrom(JdbcTemplate jdbcTemplate, String table) {
        jdbcTemplate.update("delete from " + table);
    }

    public static void assertNoSuchUser(JdbcTemplate template, String column, String value) {
        assertThat(template.queryForObject("select count(id) from users where " + column + "='" + value + "'", Integer.class)).isZero();
    }
}
