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
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.KeyPair;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

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
    public static final String PUBLIC_KEY =
        "-----BEGIN RSA PUBLIC KEY-----\n" +
            "MIGJAoGBAMStmxljvRABrtZ0MPp46/dEsEDgjknTNk6JczOgUHnKHrirSyYRI21X\n" +
            "ilrI5gTlOcfFaMyjTLuAOwaMjWiYAbrCB/Knrcj1ZwtfsUMvJ57jd8bn5v2uih+i\n" +
            "wv47MlJcRJK6WxP1jVfFIUUzlEy7gh724zj+LMosKwAqKCAyGcCZAgMBAAE=\n" +
            "-----END RSA PUBLIC KEY-----";

    public static final String PASSWORD = "password";

    public static final String ID = "id";
    private IdentityZoneProvisioning provisioning;
    private IdentityZoneConfigurationBootstrap bootstrap;
    private Map<String, String> links = new HashMap<>();
    ;

    @Before
    public void configureProvisioning() {
        provisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        bootstrap = new IdentityZoneConfigurationBootstrap(provisioning);
    }

    @Test
    public void tokenPolicy_configured_fromValuesInYaml() throws Exception {
        TokenPolicy tokenPolicy = new TokenPolicy();
        KeyPair key = new KeyPair(PRIVATE_KEY, PUBLIC_KEY, PASSWORD);
        Map<String, KeyPair> keys = new HashMap<>();
        keys.put(ID, key);
        tokenPolicy.setKeys(keys);
        tokenPolicy.setAccessTokenValidity(3600);
        bootstrap.setTokenPolicy(tokenPolicy);
        bootstrap.afterPropertiesSet();

        IdentityZone zone = provisioning.retrieve(IdentityZone.getUaa().getId());
        IdentityZoneConfiguration definition = zone.getConfig();
        assertEquals(3600, definition.getTokenPolicy().getAccessTokenValidity());
        assertEquals(PASSWORD, definition.getTokenPolicy().getKeys().get(ID).getSigningKeyPassword());
        assertEquals(PUBLIC_KEY, definition.getTokenPolicy().getKeys().get(ID).getVerificationKey());
        assertEquals(PRIVATE_KEY, definition.getTokenPolicy().getKeys().get(ID).getSigningKey());
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
}
