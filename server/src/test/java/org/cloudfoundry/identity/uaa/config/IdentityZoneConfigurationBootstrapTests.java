package org.cloudfoundry.identity.uaa.config;

import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.KeyPair;
import org.cloudfoundry.identity.uaa.zone.TokenPolicy;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;

/*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
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



    @Test
    public void tokenPolicy_configured_fromValuesInYaml() throws Exception {
        IdentityZoneProvisioning provisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        IdentityZoneConfigurationBootstrap bootstrap = new IdentityZoneConfigurationBootstrap(provisioning);
        TokenPolicy tokenPolicy = new TokenPolicy();
        KeyPair key = new KeyPair(PRIVATE_KEY, PUBLIC_KEY, PASSWORD);
        Map<String,KeyPair> keys = new HashMap<>();
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
}
