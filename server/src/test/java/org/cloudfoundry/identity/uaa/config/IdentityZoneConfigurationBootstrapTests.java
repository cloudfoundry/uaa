package org.cloudfoundry.identity.uaa.config;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.login.Prompt;
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
import org.cloudfoundry.identity.uaa.zone.UserConfig;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.certificate1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.key1;
import static org.cloudfoundry.identity.uaa.provider.saml.TestCredentialObjects.passphrase1;

@WithDatabaseContext
public class IdentityZoneConfigurationBootstrapTests {

    public static final String PRIVATE_KEY = """
            -----BEGIN RSA PRIVATE KEY-----
            MIICXAIBAAKBgQDErZsZY70QAa7WdDD6eOv3RLBA4I5J0zZOiXMzoFB5yh64q0sm
            ESNtV4payOYE5TnHxWjMo0y7gDsGjI1omAG6wgfyp63I9WcLX7FDLyee43fG5+b9
            roofosL+OzJSXESSulsT9Y1XxSFFM5RMu4Ie9uM4/izKLCsAKiggMhnAmQIDAQAB
            AoGAAs2OllALk7zSZxAE2qz6f+2krWgF3xt5fKkM0UGJpBKzWWJnkcVQwfArcpvG
            W2+A4U347mGtaEatkKxUH5d6/s37jfRI7++HFXcLf6QJPmuE3+FtB2mX0lVJoaJb
            RLh+tOtt4ZJRAt/u6RjUCVNpDnJB6NZ032bpL3DijfNkRuECQQDkJR+JJPUpQGoI
            voPqcLl0i1tLX93XE7nu1YuwdQ5SmRaS0IJMozoBLBfFNmCWlSHaQpBORc38+eGC
            J9xsOrBNAkEA3LD1JoNI+wPSo/o71TED7BoVdwCXLKPqm0TnTr2EybCUPLNoff8r
            Ngm51jXc8mNvUkBtYiPfMKzpdqqFBWXXfQJAQ7D0E2gAybWQAHouf7/kdrzmYI3Y
            L3lt4HxBzyBcGIvNk9AD6SNBEZn4j44byHIFMlIvqNmzTY0CqPCUyRP8vQJBALXm
            ANmygferKfXP7XsFwGbdBO4mBXRc0qURwNkMqiMXMMdrVGftZq9Oiua9VJRQUtPn
            mIC4cmCLVI5jc+qEC30CQE+eOXomzxNNPxVnIp5k5f+savOWBBu83J2IoT2znnGb
            wTKZHjWybPHsW2q8Z6Moz5dvE+XMd11c5NtIG2/L97I=
            -----END RSA PRIVATE KEY-----""";

    private static final String ID = "id";
    private IdentityZoneProvisioning provisioning;
    private IdentityZoneConfigurationBootstrap bootstrap;
    private final Map<String, Object> links = new HashMap<>();

    @BeforeEach
    void configureProvisioning(@Autowired JdbcTemplate jdbcTemplate) throws SQLException {
        TestUtils.cleanAndSeedDb(jdbcTemplate);
        provisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        bootstrap = new IdentityZoneConfigurationBootstrap(provisioning);

        GeneralIdentityZoneConfigurationValidator configValidator = new GeneralIdentityZoneConfigurationValidator();

        GeneralIdentityZoneValidator validator = new GeneralIdentityZoneValidator(configValidator);
        bootstrap.setValidator(validator);

        //For the SamlTestUtils keys we are using.
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    @Test
    void clientSecretPolicy() throws Exception {
        bootstrap.setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 1, 1, 1, 6));
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertThat(uaa.getConfig().getClientSecretPolicy().getMinLength()).isZero();
        assertThat(uaa.getConfig().getClientSecretPolicy().getMaxLength()).isEqualTo(255);
        assertThat(uaa.getConfig().getClientSecretPolicy().getRequireUpperCaseCharacter()).isZero();
        assertThat(uaa.getConfig().getClientSecretPolicy().getRequireLowerCaseCharacter()).isOne();
        assertThat(uaa.getConfig().getClientSecretPolicy().getRequireDigit()).isOne();
        assertThat(uaa.getConfig().getClientSecretPolicy().getRequireSpecialCharacter()).isOne();
        assertThat(uaa.getConfig().getClientSecretPolicy().getExpireSecretInMonths()).isEqualTo(-1);
    }

    @Test
    void multipleKeys() throws InvalidIdentityZoneDetailsException {
        bootstrap.setSamlSpPrivateKey(key1());
        bootstrap.setSamlSpCertificate(certificate1());
        bootstrap.setSamlSpPrivateKeyPassphrase(passphrase1());
        Map<String, Map<String, String>> keys = new HashMap<>();
        Map<String, String> key1 = new HashMap<>();
        key1.put("key", key1());
        key1.put("passphrase", passphrase1());
        key1.put("certificate", certificate1());
        keys.put("Key1", key1);
        bootstrap.setActiveKeyId("KEY1");
        bootstrap.setSamlKeys(keys);
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        SamlConfig config = uaa.getConfig().getSamlConfig();
        assertThat(config.getPrivateKey()).isEqualTo(key1());
        assertThat(config.getPrivateKeyPassword()).isEqualTo(passphrase1());
        assertThat(config.getCertificate()).isEqualTo(certificate1());

        assertThat(config.getActiveKeyId()).isEqualTo("key1");
        assertThat(config.getKeys()).hasSize(2);

        assertThat(config.getKeys().get("key1").getKey()).isEqualTo(key1());
        assertThat(config.getKeys().get("key1").getPassphrase()).isEqualTo(passphrase1());
        assertThat(config.getKeys().get("key1").getCertificate()).isEqualTo(certificate1());
    }

    @Test
    void keyIdNullException() {
        bootstrap.setSamlSpPrivateKey(key1());
        bootstrap.setSamlSpCertificate(certificate1());
        bootstrap.setSamlSpPrivateKeyPassphrase(passphrase1());
        Map<String, Map<String, String>> keys = new HashMap<>();
        Map<String, String> key1 = new HashMap<>();
        key1.put("key", key1());
        key1.put("passphrase", passphrase1());
        key1.put("certificate", certificate1());
        keys.put(null, key1);
        bootstrap.setActiveKeyId(null);
        bootstrap.setSamlKeys(keys);
        assertThatExceptionOfType(InvalidIdentityZoneDetailsException.class).isThrownBy(() -> bootstrap.afterPropertiesSet());
    }

    @Test
    void passphraseOnlyException() {
        bootstrap.setSamlSpPrivateKey(key1());
        bootstrap.setSamlSpCertificate(certificate1());
        bootstrap.setSamlSpPrivateKeyPassphrase(passphrase1());
        Map<String, Map<String, String>> keys = new HashMap<>();
        Map<String, String> key1 = new HashMap<>();
        key1.put("passphrase", passphrase1());
        keys.put("key1", key1);
        bootstrap.setActiveKeyId(null);
        bootstrap.setSamlKeys(keys);
        assertThatExceptionOfType(InvalidIdentityZoneDetailsException.class)
                .isThrownBy(() -> bootstrap.afterPropertiesSet())
                .withMessage("The zone configuration is invalid. Identity zone cannot be updated with partial Saml CertKey config.");
    }

    @Test
    void samlKeysAndSigningConfigs() throws Exception {
        bootstrap.setSamlSpPrivateKey(key1());
        bootstrap.setSamlSpCertificate(certificate1());
        bootstrap.setSamlSpPrivateKeyPassphrase(passphrase1());
        bootstrap.setSamlWantAssertionSigned(false);
        bootstrap.setSamlRequestSigned(false);
        bootstrap.afterPropertiesSet();

        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertThat(uaa.getConfig().getSamlConfig().getPrivateKey()).isEqualTo(key1());
        assertThat(uaa.getConfig().getSamlConfig().getPrivateKeyPassword()).isEqualTo(passphrase1());
        assertThat(uaa.getConfig().getSamlConfig().getCertificate()).isEqualTo(certificate1());
        assertThat(uaa.getConfig().getSamlConfig().isWantAssertionSigned()).isFalse();
        assertThat(uaa.getConfig().getSamlConfig().isRequestSigned()).isFalse();
    }

    @Test
    void enableInResponseTo() throws Exception {
        bootstrap.setDisableSamlInResponseToCheck(false);
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertThat(uaa.getConfig().getSamlConfig().isDisableInResponseToCheck()).isFalse();
    }

    @Test
    void disableInResponseTo() throws Exception {
        bootstrap.setDisableSamlInResponseToCheck(true);
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertThat(uaa.getConfig().getSamlConfig().isDisableInResponseToCheck()).isTrue();
    }

    @Test
    void defaultGroups() throws Exception {
        UserConfig defaultUserConfig = new UserConfig();
        String[] groups = {"group1", "group2", "group3"};
        defaultUserConfig.setDefaultGroups(Arrays.asList(groups));
        bootstrap.setDefaultUserConfig(defaultUserConfig);
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertThat(uaa.getConfig().getUserConfig().getDefaultGroups()).contains(groups);
    }

    @Test
    void allowedGroups() throws Exception {
        UserConfig defaultUserConfig = new UserConfig();
        String[] groups = {"group1", "group2", "group3"};
        defaultUserConfig.setDefaultGroups(Arrays.asList(groups));
        defaultUserConfig.setAllowedGroups(Arrays.asList(groups));
        bootstrap.setDefaultUserConfig(defaultUserConfig);
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertThat(uaa.getConfig().getUserConfig().resultingAllowedGroups()).contains(groups);
    }

    @Test
    void tokenPolicyConfiguredFromValuesInYaml() throws Exception {
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
        assertThat(definition.getTokenPolicy().getAccessTokenValidity()).isEqualTo(3600);
        assertThat(definition.getTokenPolicy().isRefreshTokenUnique()).isFalse();
        assertThat(definition.getTokenPolicy().getRefreshTokenFormat()).isEqualTo(JWT.getStringValue());
        assertThat(definition.getTokenPolicy().getKeys().get(ID).getSigningKey()).isEqualTo(PRIVATE_KEY);
    }

    @Test
    void disableSelfServiceLinks() throws Exception {
        bootstrap.setSelfServiceLinksEnabled(false);
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertThat(zone.getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled()).isFalse();
    }

    @Test
    void setHomeRedirect() throws Exception {
        bootstrap.setHomeRedirect("https://some.redirect.com/redirect");
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertThat(zone.getConfig().getLinks().getHomeRedirect()).isEqualTo("https://some.redirect.com/redirect");
    }

    @Test
    void signupLinkConfigured() throws Exception {
        links.put("signup", "/configured_signup");
        bootstrap.setSelfServiceLinks(links);
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertThat(zone.getConfig().getLinks().getSelfService().getSignup()).isEqualTo("/configured_signup");
        assertThat(zone.getConfig().getLinks().getSelfService().getPasswd()).isNull();
    }

    @Test
    void passwdLinkConfigured() throws Exception {
        links.put("passwd", "/configured_passwd");
        bootstrap.setSelfServiceLinks(links);
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaaZoneId());
        assertThat(zone.getConfig().getLinks().getSelfService().getSignup()).isNull();
        assertThat(zone.getConfig().getLinks().getSelfService().getPasswd()).isEqualTo("/configured_passwd");
    }

    @Test
    void logoutRedirect() throws Exception {
        bootstrap.setLogoutDefaultRedirectUrl("/configured_login");
        bootstrap.setLogoutDisableRedirectParameter(false);
        bootstrap.setLogoutRedirectParameterName("test");
        bootstrap.setLogoutRedirectWhitelist(Collections.singletonList("http://single-url"));
        bootstrap.afterPropertiesSet();
        IdentityZoneConfiguration config = provisioning.retrieve(IdentityZone.getUaaZoneId()).getConfig();
        assertThat(config.getLinks().getLogout().getRedirectUrl()).isEqualTo("/configured_login");
        assertThat(config.getLinks().getLogout().getRedirectParameterName()).isEqualTo("test");
        assertThat(config.getLinks().getLogout().getWhitelist()).isEqualTo(Collections.singletonList("http://single-url"));
        assertThat(config.getLinks().getLogout().isDisableRedirectParameter()).isFalse();
    }

    @Test
    void prompts() throws Exception {
        List<Prompt> prompts = Arrays.asList(
                new Prompt("name1", "type1", "text1"),
                new Prompt("name2", "type2", "text2")
        );
        bootstrap.setPrompts(prompts);
        bootstrap.afterPropertiesSet();
        IdentityZoneConfiguration config = provisioning.retrieve(IdentityZone.getUaaZoneId()).getConfig();
        assertThat(config.getPrompts()).isEqualTo(prompts);
    }

    @Test
    void idpDiscoveryEnabled() throws Exception {
        bootstrap.setIdpDiscoveryEnabled(true);
        bootstrap.afterPropertiesSet();
        IdentityZoneConfiguration config = provisioning.retrieve(IdentityZone.getUaaZoneId()).getConfig();
        assertThat(config.isIdpDiscoveryEnabled()).isTrue();
    }
}
