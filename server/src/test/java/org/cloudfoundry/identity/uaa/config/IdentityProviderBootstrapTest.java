package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.IdentityProviderBootstrap;
import org.cloudfoundry.identity.uaa.provider.AbstractExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderWrapper;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.KeystoneIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.RawExternalOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.OauthIDPWrapperFactoryBean;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderData;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static java.util.stream.Collectors.toList;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.KEYSTONE;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition.EMAIL_DOMAIN_ATTR;
import static org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition.PROVIDER_DESCRIPTION;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.ATTRIBUTE_MAPPINGS;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EXTERNAL_GROUPS_WHITELIST;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.STORE_CUSTOM_ATTRIBUTES_NAME;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class IdentityProviderBootstrapTest {

    private SamlIdentityProviderDefinition samlIdentityProviderDefinition;
    private SamlIdentityProviderDefinition samlIdentityProviderDefinition1;
    private BootstrapSamlIdentityProviderData configurator;
    private ApplicationEventPublisher publisher;
    private IdentityProviderProvisioning provisioning;
    private IdentityProviderBootstrap bootstrap;
    private MockEnvironment environment;
    private AbstractExternalOAuthIdentityProviderDefinition oauthProvider;
    private AbstractExternalOAuthIdentityProviderDefinition oidcProvider;
    private HashMap<String, AbstractExternalOAuthIdentityProviderDefinition> oauthProviderConfig;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setup() throws Exception {
        samlIdentityProviderDefinition = new SamlIdentityProviderDefinition();
        samlIdentityProviderDefinition.setAssertionConsumerIndex(0);
        samlIdentityProviderDefinition.setIconUrl("iconUrl");
        samlIdentityProviderDefinition.setIdpEntityAlias("alias");
        samlIdentityProviderDefinition.setLinkText("text");
        samlIdentityProviderDefinition.setMetaDataLocation("http://location");
        samlIdentityProviderDefinition.setNameID("nameId");
        samlIdentityProviderDefinition.setShowSamlLink(true);
        samlIdentityProviderDefinition.setMetadataTrustCheck(true);

        samlIdentityProviderDefinition1 = samlIdentityProviderDefinition.clone();
        samlIdentityProviderDefinition1.setIdpEntityAlias("alias2");
        samlIdentityProviderDefinition1.setMetaDataLocation("http://location2");

        oauthProvider = new RawExternalOAuthIdentityProviderDefinition();
        setCommonProperties(oauthProvider);
        oidcProvider = new OIDCIdentityProviderDefinition();
        setCommonProperties(oidcProvider);

        oauthProviderConfig = new HashMap<>();
        oauthProviderConfig.put(OAUTH20, oauthProvider);
        oauthProviderConfig.put(OIDC10, oidcProvider);


        configurator = mock(BootstrapSamlIdentityProviderData.class);
        publisher = mock(ApplicationEventPublisher.class);
        provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        environment = new MockEnvironment();
        bootstrap = new IdentityProviderBootstrap(provisioning, environment);
        bootstrap.setApplicationEventPublisher(publisher);

    }

    @Test
    void upgradeLDAPProvider() throws Exception {
        String insertSQL = "INSERT INTO identity_provider (id,identity_zone_id,name,origin_key,type,config)VALUES ('ldap','uaa','ldap','ldap2','ldap','{\"ldapdebug\":\"Test debug\",\"profile\":{\"file\":\"ldap/ldap-search-and-bind.xml\"},\"base\":{\"url\":\"ldap://localhost:389/\",\"userDn\":\"cn=admin,dc=test,dc=com\",\"password\":\"password\",\"searchBase\":\"dc=test,dc=com\",\"searchFilter\":\"cn={0}\",\"referral\":\"follow\"},\"groups\":{\"file\":\"ldap/ldap-groups-map-to-scopes.xml\",\"searchBase\":\"dc=test,dc=com\",\"groupSearchFilter\":\"member={0}\",\"searchSubtree\":true,\"maxSearchDepth\":10,\"autoAdd\":true,\"ignorePartialResultException\":true}}')";
        jdbcTemplate.update(insertSQL);
        bootstrap.afterPropertiesSet();
    }

    @Test
    void ldapProfileBootstrap() throws Exception {
        environment.setActiveProfiles(LDAP);
        bootstrap.afterPropertiesSet();

        IdentityProvider<LdapIdentityProviderDefinition> ldapProvider = provisioning.retrieveByOriginIgnoreActiveFlag(LDAP, IdentityZone.getUaaZoneId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(LDAP, ldapProvider.getType());
        LdapIdentityProviderDefinition definition = ldapProvider.getConfig();
        assertNotNull(definition);
        assertFalse(definition.isConfigured());
    }

    @Test
    void ldapBootstrap() throws Exception {
        final String idpDescription = "Test LDAP Provider Description";
        HashMap<String, Object> ldapConfig = getGenericLdapConfig();

        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider<LdapIdentityProviderDefinition> ldapProvider = provisioning.retrieveByOriginIgnoreActiveFlag(LDAP, IdentityZone.getUaaZoneId());
        validateGenericLdapProvider(ldapProvider);
    }

    private static void validateGenericLdapProvider(
            IdentityProvider<LdapIdentityProviderDefinition> ldapProvider) {
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(LDAP, ldapProvider.getType());
        assertThat(ldapProvider.getConfig().getEmailDomain(), containsInAnyOrder("test.domain"));
        assertEquals(Collections.singletonList("value"), ldapProvider.getConfig().getExternalGroupsWhitelist());
        assertEquals("first_name", ldapProvider.getConfig().getAttributeMappings().get("given_name"));
        assertEquals("Test LDAP Provider Description", ldapProvider.getConfig().getProviderDescription());
        assertFalse(ldapProvider.getConfig().isStoreCustomAttributes());
    }

    private static HashMap<String, Object> getGenericLdapConfig() {
        HashMap<String, Object> ldapConfig = new HashMap<>();

        ldapConfig.put(EMAIL_DOMAIN_ATTR, Collections.singletonList("test.domain"));
        ldapConfig.put(STORE_CUSTOM_ATTRIBUTES_NAME, false);
        ldapConfig.put(PROVIDER_DESCRIPTION, "Test LDAP Provider Description");
        List<String> attrMap = new ArrayList<>();
        attrMap.add("value");
        ldapConfig.put(EXTERNAL_GROUPS_WHITELIST, attrMap);

        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "first_name");
        ldapConfig.put(ATTRIBUTE_MAPPINGS, attributeMappings);
        return ldapConfig;
    }

    @Test
    void ldapOverrideFalse() throws Exception {
        TestUtils.cleanAndSeedDb(jdbcTemplate);
        environment.setActiveProfiles(LDAP);
        HashMap<String, Object> ldapConfig = getGenericLdapConfig();
        ldapConfig.put("override", false);

        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider<LdapIdentityProviderDefinition> ldapProvider = provisioning.retrieveByOriginIgnoreActiveFlag(LDAP, IdentityZone.getUaaZoneId());
        validateGenericLdapProvider(ldapProvider);

        ldapConfig.put(EMAIL_DOMAIN_ATTR, Arrays.asList("test.domain", "test2.domain"));
        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();
        ldapProvider = provisioning.retrieveByOriginIgnoreActiveFlag(LDAP, IdentityZone.getUaaZoneId());
        //no changes
        validateGenericLdapProvider(ldapProvider);
    }

    @Test
    void removedLdapBootstrapRemainsActive() throws Exception {
        environment.setActiveProfiles(LDAP);
        HashMap<String, Object> ldapConfig = new HashMap<>();
        ldapConfig.put("base.url", "ldap://localhost:389/");
        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider ldapProvider = provisioning.retrieveByOriginIgnoreActiveFlag(LDAP, IdentityZone.getUaaZoneId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(LDAP, ldapProvider.getType());
        assertTrue(ldapProvider.isActive());

        bootstrap.setLdapConfig(null);
        bootstrap.afterPropertiesSet();
        ldapProvider = provisioning.retrieveByOriginIgnoreActiveFlag(LDAP, IdentityZone.getUaaZoneId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(LDAP, ldapProvider.getType());
        assertFalse(ldapProvider.isActive());

        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();
        ldapProvider = provisioning.retrieveByOriginIgnoreActiveFlag(LDAP, IdentityZone.getUaaZoneId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(LDAP, ldapProvider.getType());
        assertTrue(ldapProvider.isActive());

        environment.setActiveProfiles("default");
        bootstrap.afterPropertiesSet();
        ldapProvider = provisioning.retrieveByOriginIgnoreActiveFlag(LDAP, IdentityZone.getUaaZoneId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(LDAP, ldapProvider.getType());
        assertFalse(ldapProvider.isActive());
    }

    @Test
    void keystoneProfileBootstrap() throws Exception {
        environment.setActiveProfiles(KEYSTONE);
        bootstrap.afterPropertiesSet();

        IdentityProvider<KeystoneIdentityProviderDefinition> keystoneProvider = provisioning.retrieveByOriginIgnoreActiveFlag(KEYSTONE, IdentityZone.getUaaZoneId());
        assertNotNull(keystoneProvider);
        assertEquals(new KeystoneIdentityProviderDefinition(), keystoneProvider.getConfig());
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(KEYSTONE, keystoneProvider.getType());
        assertNotNull(keystoneProvider.getConfig());
        assertNull(keystoneProvider.getConfig().getAdditionalConfiguration());
    }

    @Test
    void keystoneBootstrap() throws Exception {
        HashMap<String, Object> keystoneConfig = new HashMap<>();
        keystoneConfig.put("testkey", "testvalue");
        bootstrap.setKeystoneConfig(keystoneConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider keystoneProvider = provisioning.retrieveByOriginIgnoreActiveFlag(KEYSTONE, IdentityZone.getUaaZoneId());
        assertNotNull(keystoneProvider);
        assertEquals(new KeystoneIdentityProviderDefinition(keystoneConfig), keystoneProvider.getConfig());
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(KEYSTONE, keystoneProvider.getType());
    }

    @Test
    void removedKeystoneBootstrapIsInactive() throws Exception {
        environment.setActiveProfiles(KEYSTONE);
        HashMap<String, Object> keystoneConfig = new HashMap<>();
        keystoneConfig.put("testkey", "testvalue");
        bootstrap.setKeystoneConfig(keystoneConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider<KeystoneIdentityProviderDefinition> keystoneProvider = provisioning.retrieveByOriginIgnoreActiveFlag(KEYSTONE, IdentityZone.getUaaZoneId());
        assertNotNull(keystoneProvider);
        assertEquals(new KeystoneIdentityProviderDefinition(keystoneConfig), keystoneProvider.getConfig());
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(KEYSTONE, keystoneProvider.getType());
        assertTrue(keystoneProvider.isActive());

        bootstrap.setKeystoneConfig(null);
        bootstrap.afterPropertiesSet();
        keystoneProvider = provisioning.retrieveByOriginIgnoreActiveFlag(KEYSTONE, IdentityZone.getUaaZoneId());
        assertNotNull(keystoneProvider);
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(KEYSTONE, keystoneProvider.getType());
        assertFalse(keystoneProvider.isActive());

        bootstrap.setKeystoneConfig(keystoneConfig);
        bootstrap.afterPropertiesSet();
        keystoneProvider = provisioning.retrieveByOriginIgnoreActiveFlag(KEYSTONE, IdentityZone.getUaaZoneId());
        assertNotNull(keystoneProvider);
        assertEquals(new KeystoneIdentityProviderDefinition(keystoneConfig), keystoneProvider.getConfig());
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(KEYSTONE, keystoneProvider.getType());
        assertTrue(keystoneProvider.isActive());
    }

    @Test
    void oauthAndOidcProviderDeletion() throws Exception {
        TestUtils.cleanAndSeedDb(jdbcTemplate);
        setOauthIDPWrappers();
        bootstrap.setOriginsToDelete(new LinkedList(oauthProviderConfig.keySet()));
        bootstrap.afterPropertiesSet();
        for (Map.Entry<String, AbstractExternalOAuthIdentityProviderDefinition> provider : oauthProviderConfig.entrySet()) {
            try {
                provisioning.retrieveByOriginIgnoreActiveFlag(provider.getKey(), IdentityZone.getUaaZoneId());
                fail(String.format("Provider '%s' should not exist.", provider.getKey()));
            } catch (EmptyResultDataAccessException ignored) {
            }

        }
    }

    private void setOauthIDPWrappers() {
        List<IdentityProviderWrapper> wrappers = new LinkedList<>();
        oauthProviderConfig
                .entrySet()
                .forEach(
                        p -> {
                            IdentityProvider provider = new IdentityProvider();
                            if (p.getValue() instanceof OIDCIdentityProviderDefinition) {
                                provider.setType(OIDC10);
                            } else if (p.getValue() instanceof RawExternalOAuthIdentityProviderDefinition) {
                                provider.setType(OAUTH20);
                            }
                            wrappers.add(
                                    OauthIDPWrapperFactoryBean.getIdentityProviderWrapper(
                                            p.getKey(),
                                            p.getValue(),
                                            provider,
                                            true
                                    )
                            );
                        }
                );
        bootstrap.setOauthIdpDefinitions(wrappers);
    }

    @Test
    void oauthAndOidcProviderActivation() throws Exception {
        setOauthIDPWrappers();
        oidcProvider.setResponseType("code id_token");
        bootstrap.afterPropertiesSet();

        for (Map.Entry<String, AbstractExternalOAuthIdentityProviderDefinition> provider : oauthProviderConfig.entrySet()) {
            IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> bootstrapOauthProvider = provisioning.retrieveByOriginIgnoreActiveFlag(provider.getKey(), IdentityZone.getUaaZoneId());
            validateOauthOidcProvider(provider, bootstrapOauthProvider);
        }

        bootstrap.setOauthIdpDefinitions(null);
        bootstrap.afterPropertiesSet();
        for (Map.Entry<String, AbstractExternalOAuthIdentityProviderDefinition> provider : oauthProviderConfig.entrySet()) {
            IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> bootstrapOauthProvider = provisioning.retrieveByOriginIgnoreActiveFlag(provider.getKey(), IdentityZone.getUaaZoneId());
            assertNotNull(bootstrapOauthProvider);
            assertThat(oauthProviderConfig.values(), PredicateMatcher.has(c -> c.equals(bootstrapOauthProvider.getConfig())));
            assertNotNull(bootstrapOauthProvider.getCreated());
            assertNotNull(bootstrapOauthProvider.getLastModified());
            assertEquals(provider.getKey(), bootstrapOauthProvider.getType());
            assertTrue(bootstrapOauthProvider.isActive());
        }

    }

    private void validateOauthOidcProvider(Map.Entry<String, AbstractExternalOAuthIdentityProviderDefinition> provider, IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> bootstrapOauthProvider) {
        assertNotNull(bootstrapOauthProvider);
        assertThat(oauthProviderConfig.values(), PredicateMatcher.has(c -> c.equals(bootstrapOauthProvider.getConfig())));
        assertNotNull(bootstrapOauthProvider.getCreated());
        assertNotNull(bootstrapOauthProvider.getLastModified());
        assertEquals(provider.getKey(), bootstrapOauthProvider.getType());
        assertTrue(bootstrapOauthProvider.isActive());
        assertTrue(bootstrapOauthProvider.getConfig().isStoreCustomAttributes()); //default
        if (OIDC10.equals(provider.getKey())) {
            assertEquals("code id_token", bootstrapOauthProvider.getConfig().getResponseType());
        } else {
            assertEquals("code", bootstrapOauthProvider.getConfig().getResponseType());
        }
    }

    @Test
    void oauthAndOidcProviderOverrideFalse() throws Exception {
        setOauthIDPWrappers();
        oidcProvider.setResponseType("code id_token");
        bootstrap.afterPropertiesSet();
        for (Map.Entry<String, AbstractExternalOAuthIdentityProviderDefinition> provider : oauthProviderConfig.entrySet()) {
            IdentityProvider<AbstractExternalOAuthIdentityProviderDefinition> bootstrapOauthProvider = provisioning.retrieveByOriginIgnoreActiveFlag(provider.getKey(), IdentityZone.getUaaZoneId());
            validateOauthOidcProvider(provider, bootstrapOauthProvider);
        }
    }

    @Test
    void bootstrapFailsIfSamlAndOauthHaveTheSameAlias() throws Exception {
        oauthProviderConfig.clear();
        oauthProviderConfig.put("same-alias", oauthProvider);

        samlIdentityProviderDefinition.setIdpEntityAlias("same-alias");

        configureSamlProviders(true, samlIdentityProviderDefinition);

        setOauthIDPWrappers();
        bootstrap.setSamlProviders(configurator);
        assertThrows(IllegalArgumentException.class, () -> bootstrap.afterPropertiesSet());
    }

    private AbstractExternalOAuthIdentityProviderDefinition setCommonProperties(AbstractExternalOAuthIdentityProviderDefinition definition) throws MalformedURLException {
        return definition
                .setAuthUrl(new URL("http://auth.url"))
                .setLinkText("link text")
                .setRelyingPartyId("relaying party id")
                .setRelyingPartySecret("relaying party secret")
                .setShowLinkText(true)
                .setSkipSslValidation(true)
                .setTokenKey("key")
                .setTokenKeyUrl(new URL("http://token.key.url"));
    }

    @Test
    void samlBootstrap() throws Exception {
        bootstrap.setSamlProviders(configurator);
        configureSamlProviders(true, samlIdentityProviderDefinition);

        bootstrap.afterPropertiesSet();

        IdentityProvider samlProvider = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider);
        samlIdentityProviderDefinition.setZoneId(IdentityZone.getUaaZoneId());
        assertEquals(samlIdentityProviderDefinition, samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider.getType());
    }

    @Test
    void providersDeletedAndNotCreated() throws Exception {
        configureSamlProviders(true, samlIdentityProviderDefinition, samlIdentityProviderDefinition1);
        List<String> originsToDelete = Arrays.asList(
                samlIdentityProviderDefinition.getIdpEntityAlias(),
                OIDC10
        );

        bootstrap.setSamlProviders(configurator);
        setOauthIDPWrappers();
        bootstrap.afterPropertiesSet();
        ContextRefreshedEvent event = new ContextRefreshedEvent(mock(ApplicationContext.class));
        bootstrap.onApplicationEvent(event);
        bootstrap.setOriginsToDelete(originsToDelete);
        bootstrap.afterPropertiesSet();
        bootstrap.onApplicationEvent(event);

        ArgumentCaptor<EntityDeletedEvent<IdentityProvider>> captor = ArgumentCaptor.forClass(EntityDeletedEvent.class);
        verify(publisher, times(2)).publishEvent(captor.capture());
        assertThat(
                captor
                        .getAllValues()
                        .stream()
                        .map(
                                p -> p.getDeleted().getOriginKey()
                        ).collect(toList()
                ),
                containsInAnyOrder(originsToDelete.toArray())
        );
    }

    private void configureSamlProviders(boolean override, SamlIdentityProviderDefinition... definitions) {
        reset(configurator);
        List<IdentityProviderWrapper<SamlIdentityProviderDefinition>> wrappers = new LinkedList<>();
        for (SamlIdentityProviderDefinition def : definitions) {
            IdentityProviderWrapper w = new IdentityProviderWrapper(
                    BootstrapSamlIdentityProviderData.parseSamlProvider(def)
            );
            w.setOverride(override);
            wrappers.add(
                    w
            );
        }
        when(configurator.getSamlProviders()).thenReturn(wrappers);
    }

    @Test
    void samlProviderOverrideFalse() throws Exception {
        configureSamlProviders(true, samlIdentityProviderDefinition, samlIdentityProviderDefinition1);
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        IdentityProvider<SamlIdentityProviderDefinition> samlProvider = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        IdentityProvider<SamlIdentityProviderDefinition> samlProvider2 = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition1.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider);
        assertNotNull(samlProvider2);
        assertEquals("http://location", samlProvider.getConfig().getMetaDataLocation());
        assertEquals("http://location2", samlProvider2.getConfig().getMetaDataLocation());

        samlIdentityProviderDefinition.setMetaDataLocation("http://some.other.location");
        samlIdentityProviderDefinition1.setMetaDataLocation("http://some.other.location");
        configureSamlProviders(false, samlIdentityProviderDefinition, samlIdentityProviderDefinition1);
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        samlProvider2 = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition1.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider);
        assertNotNull(samlProvider2);
        assertEquals("http://location", samlProvider.getConfig().getMetaDataLocation());
        assertEquals("http://location2", samlProvider2.getConfig().getMetaDataLocation());


    }

    @Test
    void samlProviderNotDeactivated() throws Exception {
        configureSamlProviders(true, samlIdentityProviderDefinition, samlIdentityProviderDefinition1);
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        IdentityProvider samlProvider = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider);
        samlIdentityProviderDefinition.setZoneId(IdentityZone.getUaaZoneId());
        assertEquals(samlIdentityProviderDefinition, samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider.getType());
        assertTrue(samlProvider.isActive());

        IdentityProvider samlProvider2 = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition1.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider2);
        samlIdentityProviderDefinition1.setZoneId(IdentityZone.getUaaZoneId());
        assertEquals(samlIdentityProviderDefinition1, samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider2.getType());
        assertTrue(samlProvider2.isActive());

        configureSamlProviders(true, samlIdentityProviderDefinition);
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider);
        assertEquals(samlIdentityProviderDefinition, samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider.getType());
        assertTrue(samlProvider.isActive());

        samlProvider2 = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition1.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider2);
        assertEquals(samlIdentityProviderDefinition1, samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider2.getType());
        assertTrue(samlProvider2.isActive());

        configureSamlProviders(true, samlIdentityProviderDefinition1);
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider);
        assertEquals(samlIdentityProviderDefinition, samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider.getType());
        assertTrue(samlProvider.isActive());

        samlProvider2 = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition1.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider2);
        assertEquals(samlIdentityProviderDefinition1, samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider2.getType());
        assertTrue(samlProvider2.isActive());

        configurator = mock(BootstrapSamlIdentityProviderData.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(new LinkedList<>());
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider);
        assertEquals(samlIdentityProviderDefinition, samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider.getType());
        assertTrue(samlProvider.isActive());

        samlProvider2 = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition1.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider2);
        assertEquals(samlIdentityProviderDefinition1, samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider2.getType());
        assertTrue(samlProvider2.isActive());

        configurator = mock(BootstrapSamlIdentityProviderData.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(samlIdentityProviderDefinition1, samlIdentityProviderDefinition));
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider);
        assertEquals(samlIdentityProviderDefinition, samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider.getType());
        assertTrue(samlProvider.isActive());

        samlProvider2 = provisioning.retrieveByOriginIgnoreActiveFlag(samlIdentityProviderDefinition1.getIdpEntityAlias(), IdentityZone.getUaaZoneId());
        assertNotNull(samlProvider2);
        assertEquals(samlIdentityProviderDefinition1, samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider2.getType());
        assertTrue(samlProvider2.isActive());
    }

    @Test
    void setInternalUserManagementEnabled() throws Exception {
        setDisableInternalUserManagement("false");
    }

    @Test
    void setInternalUserManagementDisabled() throws Exception {
        setDisableInternalUserManagement("true");
    }

    @Test
    void setInternalUserManagementNotSet() throws Exception {
        setDisableInternalUserManagement(null);
    }

    private void setDisableInternalUserManagement(String expectedValue) throws Exception {
        bootstrap.setDisableInternalUserManagement(Boolean.parseBoolean(expectedValue));
        bootstrap.afterPropertiesSet();
        IdentityProvider<UaaIdentityProviderDefinition> internalIDP = provisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, IdentityZone.getUaaZoneId());

        if (expectedValue == null) {
            expectedValue = "false";
        }
        assertEquals(Boolean.valueOf(expectedValue), internalIDP.getConfig().isDisableInternalUserManagement());
    }

    @Test
    void setPasswordPolicyToInternalIDP() throws Exception {
        bootstrap.setDefaultPasswordPolicy(new PasswordPolicy(123, 4567, 1, 0, 1, 0, 6));
        bootstrap.afterPropertiesSet();

        IdentityProvider<UaaIdentityProviderDefinition> internalIDP = provisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        PasswordPolicy passwordPolicy = internalIDP.getConfig().getPasswordPolicy();
        assertEquals(123, passwordPolicy.getMinLength());
        assertEquals(4567, passwordPolicy.getMaxLength());
        assertEquals(1, passwordPolicy.getRequireUpperCaseCharacter());
        assertEquals(0, passwordPolicy.getRequireLowerCaseCharacter());
        assertEquals(1, passwordPolicy.getRequireDigit());
        assertEquals(0, passwordPolicy.getRequireSpecialCharacter());
        assertEquals(6, passwordPolicy.getExpirePasswordInMonths());
    }

    @Test
    void setLockoutPolicyToInternalIDP() throws Exception {
        LockoutPolicy lockoutPolicy = new LockoutPolicy();
        lockoutPolicy.setLockoutPeriodSeconds(123);
        lockoutPolicy.setLockoutAfterFailures(3);
        lockoutPolicy.setCountFailuresWithin(343);
        bootstrap.setDefaultLockoutPolicy(lockoutPolicy);
        bootstrap.afterPropertiesSet();

        IdentityProvider<UaaIdentityProviderDefinition> internalIDP = provisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        lockoutPolicy = internalIDP.getConfig().getLockoutPolicy();

        assertEquals(123, lockoutPolicy.getLockoutPeriodSeconds());
        assertEquals(3, lockoutPolicy.getLockoutAfterFailures());
        assertEquals(343, lockoutPolicy.getCountFailuresWithin());
    }

    @Test
    void deactivateAndActivateInternalIDP() throws Exception {
        environment.setProperty("disableInternalAuth", "true");
        bootstrap.afterPropertiesSet();

        IdentityProvider internalIdp = provisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        assertFalse(internalIdp.isActive());

        environment.setProperty("disableInternalAuth", "false");
        bootstrap.afterPropertiesSet();

        internalIdp = provisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        assertTrue(internalIdp.isActive());
    }

    @Test
    void defaultActiveFlagOnInternalIDP() throws Exception {
        bootstrap.afterPropertiesSet();
        IdentityProvider internalIdp = provisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, IdentityZone.getUaaZoneId());
        assertTrue(internalIdp.isActive());
    }
}
