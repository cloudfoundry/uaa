/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.login.Prompt;
import org.cloudfoundry.identity.uaa.zone.ClientSecretPolicy;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlTestUtils;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TokenFormat.JWT;
import static org.junit.Assert.*;

public class IdentityZoneConfigurationBootstrapTests extends JdbcTestBase {

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

    public static final String PASSWORD = "password";

    public static final String ID = "id";
    private IdentityZoneProvisioning provisioning;
    private IdentityZoneConfigurationBootstrap bootstrap;
    private Map<String, String> links = new HashMap<>();


    @Before
    public void configureProvisioning() {
        provisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        bootstrap = new IdentityZoneConfigurationBootstrap(provisioning);
    }

    @Test
    public void testClientSecretPolicy() throws Exception {
        bootstrap.setClientSecretPolicy(new ClientSecretPolicy(0, 255, 0, 1, 1, 1, 6));
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaa().getId());
        assertEquals(0, uaa.getConfig().getClientSecretPolicy().getMinLength());
        assertEquals(255, uaa.getConfig().getClientSecretPolicy().getMaxLength());
        assertEquals(0, uaa.getConfig().getClientSecretPolicy().getRequireUpperCaseCharacter());
        assertEquals(1, uaa.getConfig().getClientSecretPolicy().getRequireLowerCaseCharacter());
        assertEquals(1, uaa.getConfig().getClientSecretPolicy().getRequireDigit());
        assertEquals(1, uaa.getConfig().getClientSecretPolicy().getRequireSpecialCharacter());
        assertEquals(6, uaa.getConfig().getClientSecretPolicy().getExpireInMonths());
    }

    @Test
    public void testDefaultSamlKeys() throws Exception {
        bootstrap.setSamlSpPrivateKey(SamlTestUtils.PROVIDER_PRIVATE_KEY);
        bootstrap.setSamlSpCertificate(SamlTestUtils.PROVIDER_CERTIFICATE);
        bootstrap.setSamlSpPrivateKeyPassphrase(SamlTestUtils.PROVIDER_PRIVATE_KEY_PASSWORD);
        bootstrap.afterPropertiesSet();
        IdentityZone uaa = provisioning.retrieve(IdentityZone.getUaa().getId());
        assertEquals(SamlTestUtils.PROVIDER_PRIVATE_KEY, uaa.getConfig().getSamlConfig().getPrivateKey());
        assertEquals(SamlTestUtils.PROVIDER_PRIVATE_KEY_PASSWORD, uaa.getConfig().getSamlConfig().getPrivateKeyPassword());
        assertEquals(SamlTestUtils.PROVIDER_CERTIFICATE, uaa.getConfig().getSamlConfig().getCertificate());
    }

    @Test
    public void tokenPolicy_configured_fromValuesInYaml() throws Exception {
        TokenPolicy tokenPolicy = new TokenPolicy();
        Map<String, String> keys = new HashMap<>();
        keys.put(ID, PRIVATE_KEY);
        tokenPolicy.setKeys(keys);
        tokenPolicy.setAccessTokenValidity(3600);
        tokenPolicy.setRefreshTokenFormat("jwt");
        tokenPolicy.setRefreshTokenUnique(false);
        bootstrap.setTokenPolicy(tokenPolicy);

        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaa().getId());
        IdentityZoneConfiguration definition = zone.getConfig();
        assertEquals(3600, definition.getTokenPolicy().getAccessTokenValidity());
        assertEquals(false, definition.getTokenPolicy().isRefreshTokenUnique());
        assertEquals(JWT.getStringValue(), definition.getTokenPolicy().getRefreshTokenFormat());
        assertEquals(PRIVATE_KEY, definition.getTokenPolicy().getKeys().get(ID));
    }

    @Test
    public void disable_self_service_links() throws Exception {
        bootstrap.setSelfServiceLinksEnabled(false);
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaa().getId());
        assertFalse(zone.getConfig().getLinks().getSelfService().isSelfServiceLinksEnabled());
    }

    @Test
    public void set_home_redirect() throws Exception {
        bootstrap.setHomeRedirect("http://some.redirect.com/redirect");
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaa().getId());
        assertEquals("http://some.redirect.com/redirect", zone.getConfig().getLinks().getHomeRedirect());
    }

    @Test
    public void null_home_redirect() throws Exception {
        bootstrap.setHomeRedirect("null");
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaa().getId());
        assertNull(zone.getConfig().getLinks().getHomeRedirect());
    }

    @Test
    public void signup_link_configured() throws Exception {
        links.put("signup", "/configured_signup");
        bootstrap.setSelfServiceLinks(links);
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaa().getId());
        assertEquals("/configured_signup", zone.getConfig().getLinks().getSelfService().getSignup());
        assertEquals("/forgot_password", zone.getConfig().getLinks().getSelfService().getPasswd());
    }

    @Test
    public void passwd_link_configured() throws Exception {
        links.put("passwd", "/configured_passwd");
        bootstrap.setSelfServiceLinks(links);
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaa().getId());
        assertEquals("/create_account", zone.getConfig().getLinks().getSelfService().getSignup());
        assertEquals("/configured_passwd", zone.getConfig().getLinks().getSelfService().getPasswd());
    }

    @Test
    public void test_logout_redirect() throws Exception {
        bootstrap.setLogoutDefaultRedirectUrl("/configured_login");
        bootstrap.setLogoutDisableRedirectParameter(false);
        bootstrap.setLogoutRedirectParameterName("test");
        bootstrap.setLogoutRedirectWhitelist(Arrays.asList("http://single-url"));
        bootstrap.afterPropertiesSet();
        IdentityZoneConfiguration config = provisioning.retrieve(IdentityZone.getUaa().getId()).getConfig();
        assertEquals("/configured_login", config.getLinks().getLogout().getRedirectUrl());
        assertEquals("test", config.getLinks().getLogout().getRedirectParameterName());
        assertEquals(Arrays.asList("http://single-url"), config.getLinks().getLogout().getWhitelist());
        assertFalse(config.getLinks().getLogout().isDisableRedirectParameter());
    }


    @Test
    public void test_prompts() throws Exception {
        List<Prompt> prompts = Arrays.asList(
            new Prompt("name1", "type1", "text1"),
            new Prompt("name2", "type2", "text2")
        );
        bootstrap.setPrompts(prompts);
        bootstrap.afterPropertiesSet();
        IdentityZoneConfiguration config = provisioning.retrieve(IdentityZone.getUaa().getId()).getConfig();
        assertEquals(prompts, config.getPrompts());
    }

    @Test
    public void idpDiscoveryEnabled() throws Exception {
        bootstrap.setIdpDiscoveryEnabled(true);
        bootstrap.afterPropertiesSet();
        IdentityZoneConfiguration config = provisioning.retrieve(IdentityZone.getUaa().getId()).getConfig();
        assertTrue(config.isIdpDiscoveryEnabled());
    }
}
