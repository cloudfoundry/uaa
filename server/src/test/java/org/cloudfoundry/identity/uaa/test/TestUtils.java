package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.client.ClientAdminBootstrap;
import org.cloudfoundry.identity.uaa.impl.config.IdentityProviderBootstrap;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.mfa.MfaProviderBootstrap;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderData;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimExternalGroupBootstrap;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimGroupBootstrap;
import org.cloudfoundry.identity.uaa.scim.bootstrap.ScimUserBootstrap;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

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

    public static void restoreToDefaults(ApplicationContext applicationContext) {
        cleanAndMigrateDb(applicationContext);
        resetIdentityZoneHolder(applicationContext);
    }

    private static void cleanAndMigrateDb(ApplicationContext applicationContext) {
        if (applicationContext == null) {
            return;
        }

        Flyway flyway;

        try {
            flyway = applicationContext.getBean(Flyway.class);
        } catch (NoSuchBeanDefinitionException ignored) {
            return;
        }

        flyway.clean();
        flyway.migrate();

        bootstrapDb(applicationContext);
    }

    private static void bootstrapDb(ApplicationContext applicationContext) {
        tryCallAfterPropertiesSet(applicationContext, IdentityZoneConfigurationBootstrap.class);
        tryCallAfterPropertiesSet(applicationContext, ScimExternalGroupBootstrap.class);
        tryCallAfterPropertiesSet(applicationContext, BootstrapSamlIdentityProviderData.class);
        tryCallAfterPropertiesSet(applicationContext, IdentityProviderBootstrap.class);
        tryCallAfterPropertiesSet(applicationContext, MfaProviderBootstrap.class);
        tryCallAfterPropertiesSet(applicationContext, ScimGroupBootstrap.class);
        tryCallAfterPropertiesSet(applicationContext, ScimUserBootstrap.class);

        try {
            ClientAdminBootstrap bootstrap = applicationContext.getBean("defaultClientAdminBootstrap", ClientAdminBootstrap.class);
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
            return;
        }

        try {
            IdentityZoneHolder.setProvisioning(applicationContext.getBean(JdbcIdentityZoneProvisioning.class));
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
        assertThat(template.queryForObject("select count(id) from users where " + column + "='" + value + "'", Integer.class), is(0));
    }
}
