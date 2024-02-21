package org.cloudfoundry.identity.uaa.config;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.zone.GeneralIdentityZoneConfigurationValidator;
import org.cloudfoundry.identity.uaa.zone.GeneralIdentityZoneValidator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.InvalidIdentityZoneDetailsException;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import java.security.Security;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@WithDatabaseContext
public class IdentityZoneConfigurationBootstrapTests {

    public static final String PRIVATE_KEY =
            "-----BEGIN RSA PRIVATE KEY-----\n" +
                    "MIICXAIBAAKBgQDErZsZY70QAa7WdDD6eOv3RLBA4I5J0zZOiXMzoFB5yh64q0sm\n" +
                    "ESNtV4payOYE5TnHxWjMo0y7gDsGjI1omAG6wgfyp63I9WcLX7FDLyee43fG5+b9\n" +
                    "roofosL+OzJSXESSulsT9Y1XxSFFM5RMu4Ie9uM4/izKLCsAKiggMhnAmQIDAQAB\n" +
                    "AoGAAs2OllALk7zSZxAE2qz6f+2krWgF3xt5fKkM0UGJpBKzWWJnkcVQwfArcpvG\n" +
                    "W2+A4U347mGtaEatkKxUH5d6/s37jfRI7++HFXcLf6QJPmuE3+FtB2mX0lVJoaJb\n" +
                    "RLh+tOtt4ZJRAt/u6RjUCVNpDnJB6NZ032bpL3DijfNkRuECQQDkJR+JJPUpQGoI\n" +
                    "voPqcLl0i1tLX93XE7nu1YuwdQ5SmRaS0IJMozoBLBfFNmCWlSHaQpBORc38+eGC\n" +
                    "J9xsOrBNAkEA3LD1JoNI+wPSo/o71TED7BoVdwCXLKPqm0TnTr2EybCUPLNoff8r\n" +
                    "Ngm51jXc8mNvUkBtYiPfMKzpdqqFBWXXfQJAQ7D0E2gAybWQAHouf7/kdrzmYI3Y\n" +
                    "L3lt4HxBzyBcGIvNk9AD6SNBEZn4j44byHIFMlIvqNmzTY0CqPCUyRP8vQJBALXm\n" +
                    "ANmygferKfXP7XsFwGbdBO4mBXRc0qURwNkMqiMXMMdrVGftZq9Oiua9VJRQUtPn\n" +
                    "mIC4cmCLVI5jc+qEC30CQE+eOXomzxNNPxVnIp5k5f+savOWBBu83J2IoT2znnGb\n" +
                    "wTKZHjWybPHsW2q8Z6Moz5dvE+XMd11c5NtIG2/L97I=\n" +
                    "-----END RSA PRIVATE KEY-----";

    private static final String ID = "id";
    private IdentityZoneProvisioning provisioning;
    private IdentityZoneConfigurationBootstrap bootstrap;
    private Map<String, Object> links = new HashMap<>();
    private GeneralIdentityZoneValidator validator;

    @BeforeEach
    void configureProvisioning(@Autowired JdbcTemplate jdbcTemplate) throws SQLException {
        TestUtils.cleanAndSeedDb(jdbcTemplate);
        provisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        bootstrap = new IdentityZoneConfigurationBootstrap(provisioning);

        GeneralIdentityZoneConfigurationValidator configValidator = new GeneralIdentityZoneConfigurationValidator();

        validator = new GeneralIdentityZoneValidator(configValidator);
        bootstrap.setValidator(validator);

        //For the SamlTestUtils keys we are using.
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @Test
    void testClientSecretPolicy() throws Exception {
        bootstrap.setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 1, 1, 1, 6));
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertEquals(0, uaa.getConfig().getClientSecretPolicy().getMinLength());
        assertEquals(255, uaa.getConfig().getClientSecretPolicy().getMaxLength());
        assertEquals(0, uaa.getConfig().getClientSecretPolicy().getRequireUpperCaseCharacter());
        assertEquals(1, uaa.getConfig().getClientSecretPolicy().getRequireLowerCaseCharacter());
        assertEquals(1, uaa.getConfig().getClientSecretPolicy().getRequireDigit());
        assertEquals(1, uaa.getConfig().getClientSecretPolicy().getRequireSpecialCharacter());
        assertEquals(-1, uaa.getConfig().getClientSecretPolicy().getExpireSecretInMonths());
    }

    @Test
    void test_multiple_keys() throws InvalidIdentityZoneDetailsException {
        bootstrap.setSamlSpPrivateKey(SamlTestUtils.PROVIDER_PRIVATE_KEY);
        bootstrap.setSamlSpCertificate(SamlTestUtils.PROVIDER_CERTIFICATE);
        bootstrap.setSamlSpPrivateKeyPassphrase(SamlTestUtils.PROVIDER_PRIVATE_KEY_PASSWORD);
        Map<String, Map<String, String>> keys = new HashMap<>();
        Map<String, String> key1 = new HashMap<>();
        key1.put("key", SamlTestUtils.PROVIDER_PRIVATE_KEY);
        key1.put("passphrase", SamlTestUtils.PROVIDER_PRIVATE_KEY_PASSWORD);
        key1.put("certificate", SamlTestUtils.PROVIDER_CERTIFICATE);
        keys.put("Key1", key1);
        bootstrap.setActiveKeyId("KEY1");
        bootstrap.setSamlKeys(keys);
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        SamlConfig config = uaa.getConfig().getSamlConfig();
        assertEquals(SamlTestUtils.PROVIDER_PRIVATE_KEY, config.getPrivateKey());
        assertEquals(SamlTestUtils.PROVIDER_PRIVATE_KEY_PASSWORD, config.getPrivateKeyPassword());
        assertEquals(SamlTestUtils.PROVIDER_CERTIFICATE, config.getCertificate());

        assertEquals("key1", config.getActiveKeyId());
        assertEquals(2, config.getKeys().size());

        assertEquals(SamlTestUtils.PROVIDER_PRIVATE_KEY, config.getKeys().get("key1").getKey());
        assertEquals(SamlTestUtils.PROVIDER_PRIVATE_KEY_PASSWORD, config.getKeys().get("key1").getPassphrase());
        assertEquals(SamlTestUtils.PROVIDER_CERTIFICATE, config.getKeys().get("key1").getCertificate());
    }

    @Test
    void test_keyId_null_exception() {
        bootstrap.setSamlSpPrivateKey(SamlTestUtils.PROVIDER_PRIVATE_KEY);
        bootstrap.setSamlSpCertificate(SamlTestUtils.PROVIDER_CERTIFICATE);
        bootstrap.setSamlSpPrivateKeyPassphrase(SamlTestUtils.PROVIDER_PRIVATE_KEY_PASSWORD);
        Map<String, Map<String, String>> keys = new HashMap<>();
        Map<String, String> key1 = new HashMap<>();
        key1.put("key", SamlTestUtils.PROVIDER_PRIVATE_KEY);
        key1.put("passphrase", SamlTestUtils.PROVIDER_PRIVATE_KEY_PASSWORD);
        key1.put("certificate", SamlTestUtils.PROVIDER_CERTIFICATE);
        keys.put(null, key1);
        bootstrap.setActiveKeyId(null);
        bootstrap.setSamlKeys(keys);
        assertThrows(InvalidIdentityZoneDetailsException.class, () -> bootstrap.afterPropertiesSet());
    }

    @Test
    void testDefaultSamlKeys() throws Exception {
        bootstrap.setSamlSpPrivateKey(SamlTestUtils.PROVIDER_PRIVATE_KEY);
        bootstrap.setSamlSpCertificate(SamlTestUtils.PROVIDER_CERTIFICATE);
        bootstrap.setSamlSpPrivateKeyPassphrase(SamlTestUtils.PROVIDER_PRIVATE_KEY_PASSWORD);
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertEquals(SamlTestUtils.PROVIDER_PRIVATE_KEY, uaa.getConfig().getSamlConfig().getPrivateKey());
        assertEquals(SamlTestUtils.PROVIDER_PRIVATE_KEY_PASSWORD, uaa.getConfig().getSamlConfig().getPrivateKeyPassword());
        assertEquals(SamlTestUtils.PROVIDER_CERTIFICATE, uaa.getConfig().getSamlConfig().getCertificate());
    }

    @Test
    void enable_in_response_to() throws Exception {
        bootstrap.setDisableSamlInResponseToCheck(false);
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertFalse(uaa.getConfig().getSamlConfig().isDisableInResponseToCheck());
    }

    @Test
    void saml_disable_in_response_to() throws Exception {
        bootstrap.setDisableSamlInResponseToCheck(true);
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertTrue(uaa.getConfig().getSamlConfig().isDisableInResponseToCheck());
    }

    @Test
    void testDefaultGroups() throws Exception {
        String[] groups = {"group1", "group2", "group3"};
        bootstrap.setDefaultUserGroups(Arrays.asList(groups));
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertThat(uaa.getConfig().getUserConfig().getDefaultGroups(), containsInAnyOrder(groups));
    }

    @Test
    void testAllowedGroups() throws Exception {
        String[] groups = {"group1", "group2", "group3"};
        bootstrap.setDefaultUserGroups(Arrays.asList(groups));
        bootstrap.setAllowedUserGroups(Arrays.asList(groups));
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertThat(uaa.getConfig().getUserConfig().resultingAllowedGroups(), containsInAnyOrder(groups));
    }

    @Test
    void tokenPolicy_configured_fromValuesInYaml() throws Exception {
        TokenPolicy tokenPolicy = new TokenPolicy();
        Map<String, String> keys = new HashMap<>();
        keys.put(ID, PRIVATE_KEY);
        tokenPolicy.setKeys(keys);
        tokenPolicy.setAccessTokenValidity(3600);
        tokenPolicy.setRefreshTokenFormat("jwt");
        tokenPolicy.setRefreshTokenUnique(false);
        bootstrap.setTokenPolicy(tokenPolicy);

        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaaZoneId());
        IdentityZoneConfiguration definition = zone.getConfig();
        assertEquals(3600, definition.getTokenPolicy().getAccessTokenValidity());
        assertFalse(definition.getTokenPolicy().isRefreshTokenUnique());
        assertEquals(JWT.getStringValue(), definition.getTokenPolicy().getRefreshTokenFormat());
        assertEquals(PRIVATE_KEY, definition.getTokenPolicy().getKeys().get(ID).getSigningKey());
    }

    @Test
    void disable_self_service_links() throws Exception {
        bootstrap.setSelfServiceLinksEnabled(false);
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertFalse(zone.getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled());
    }

    @Test
    void set_home_redirect() throws Exception {
        bootstrap.setHomeRedirect("http://some.redirect.com/redirect");
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertEquals("http://some.redirect.com/redirect", zone.getConfig().getLinks().getHomeRedirect());
    }

    @Test
    void signup_link_configured() throws Exception {
        links.put("signup", "/configured_signup");
        bootstrap.setSelfServiceLinks(links);
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertEquals("/configured_signup", zone.getConfig().getLinks().getSelfService().getSignup());
        assertNull(zone.getConfig().getLinks().getSelfService().getPasswd());
    }

    @Test
    void passwd_link_configured() throws Exception {
        links.put("passwd", "/configured_passwd");
        bootstrap.setSelfServiceLinks(links);
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertNull(zone.getConfig().getLinks().getSelfService().getSignup());
        assertEquals("/configured_passwd", zone.getConfig().getLinks().getSelfService().getPasswd());
    }

    @Test
    void test_logout_redirect() throws Exception {
        bootstrap.setLogoutDefaultRedirectUrl("/configured_login");
        bootstrap.setLogoutDisableRedirectParameter(false);
        bootstrap.setLogoutRedirectParameterName("test");
        bootstrap.setLogoutRedirectWhitelist(Collections.singletonList("http://single-url"));
        bootstrap.afterPropertiesSet();
        IdentityZoneConfiguration config = provisioning.retrieve(IdentityZone.getUaaZoneId()).getConfig();
        assertEquals("/configured_login", config.getLinks().getLogout().getRedirectUrl());
        assertEquals("test", config.getLinks().getLogout().getRedirectParameterName());
        assertEquals(Collections.singletonList("http://single-url"), config.getLinks().getLogout().getWhitelist());
        assertFalse(config.getLinks().getLogout().isDisableRedirectParameter());
    }


    @Test
    void test_prompts() throws Exception {
        List<Prompt> prompts = Arrays.asList(
                new Prompt("name1", "type1", "text1"),
                new Prompt("name2", "type2", "text2")
        );
        bootstrap.setPrompts(prompts);
        bootstrap.afterPropertiesSet();
        IdentityZoneConfiguration config = provisioning.retrieve(IdentityZone.getUaaZoneId()).getConfig();
        assertEquals(prompts, config.getPrompts());
    }

    @Test
    void idpDiscoveryEnabled() throws Exception {
        bootstrap.setIdpDiscoveryEnabled(true);
        bootstrap.afterPropertiesSet();
        IdentityZoneConfiguration config = provisioning.retrieve(IdentityZone.getUaaZoneId()).getConfig();
        assertTrue(config.isIdpDiscoveryEnabled());
    }
}
