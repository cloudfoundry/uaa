/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.cert.CertificateException;
import java.util.Map;

import static java.util.Collections.EMPTY_MAP;
import static org.cloudfoundry.identity.uaa.zone.SamlConfig.LEGACY_KEY_ID;
import static org.junit.Assert.*;

public class SamlConfigTest {


    @Rule
    public ExpectedException exception = ExpectedException.none();

    String oldJson =
        "{\n" +
        "    \"assertionSigned\": true,\n" +
        "    \"assertionTimeToLiveSeconds\": 600,\n" +
        "    \"certificate\": \"-----BEGIN CERTIFICATE-----\\nMIID4zCCA0ygAwIBAgIJAJdmwmBdhEydMA0GCSqGSIb3DQEBBQUAMIGoMQswCQYD\\nVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xJzAl\\nBgNVBAoTHkNsb3VkIEZvdW5kcnkgRm91bmRhdGlvbiwgSW5jLjEMMAoGA1UECxMD\\nVUFBMRIwEAYDVQQDEwlsb2NhbGhvc3QxKTAnBgkqhkiG9w0BCQEWGmNmLWlkZW50\\naXR5LWVuZ0BwaXZvdGFsLmlvMB4XDTE2MDIxNjIyMTMzN1oXDTE2MDMxNzIyMTMz\\nN1owgagxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZy\\nYW5jaXNjbzEnMCUGA1UEChMeQ2xvdWQgRm91bmRyeSBGb3VuZGF0aW9uLCBJbmMu\\nMQwwCgYDVQQLEwNVQUExEjAQBgNVBAMTCWxvY2FsaG9zdDEpMCcGCSqGSIb3DQEJ\\nARYaY2YtaWRlbnRpdHktZW5nQHBpdm90YWwuaW8wgZ8wDQYJKoZIhvcNAQEBBQAD\\ngY0AMIGJAoGBAKmeo9CIMJ8ljWFVpBRkbpGzVZ3cWY/URK03vWFd5c4uiDme+lof\\njk/e/v0Qalo7Tq8fmpK7/GvqRBEE4DiH06pcZLvYEZAEfyMw0KgeqAmsgANBMdcf\\nzlFgXfxsfphynXyNyHQpWZjAp6Jos18wOeCcC/rAwM40nPvrUYG2sbX/AgMBAAGj\\nggERMIIBDTAdBgNVHQ4EFgQUdiixDfiZ61ljk7J/uUYcay26n5swgd0GA1UdIwSB\\n1TCB0oAUdiixDfiZ61ljk7J/uUYcay26n5uhga6kgaswgagxCzAJBgNVBAYTAlVT\\nMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEnMCUGA1UEChMe\\nQ2xvdWQgRm91bmRyeSBGb3VuZGF0aW9uLCBJbmMuMQwwCgYDVQQLEwNVQUExEjAQ\\nBgNVBAMTCWxvY2FsaG9zdDEpMCcGCSqGSIb3DQEJARYaY2YtaWRlbnRpdHktZW5n\\nQHBpdm90YWwuaW+CCQCXZsJgXYRMnTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB\\nBQUAA4GBAAPf/SPl/LuVYrl0HDUU8YDR3N7Fi4OjhF3+n+uBYRhO+9IbQ/t1sC1p\\nenWhiAfyZtgFv2OmjvtFyty9YqHhIPAg9Ceod37Q7HNSG04vbYHNJ6XhGUzacMj8\\nhQ1ZzQBv+CaKWZarBIql/TsxtpvvXhaE4QqR4NvUDnESHtxefriv\\n-----END CERTIFICATE-----\\n\",\n" +
        "    \"privateKey\": \"-----BEGIN RSA PRIVATE KEY-----\\nMIICXAIBAAKBgQCpnqPQiDCfJY1hVaQUZG6Rs1Wd3FmP1EStN71hXeXOLog5nvpa\\nH45P3v79EGpaO06vH5qSu/xr6kQRBOA4h9OqXGS72BGQBH8jMNCoHqgJrIADQTHX\\nH85RYF38bH6Ycp18jch0KVmYwKeiaLNfMDngnAv6wMDONJz761GBtrG1/wIDAQAB\\nAoGAPjYeNSzOUICwcyO7E3Omji/tVgHso3EiYznPbvfGgrHUavXhMs7iHm9WrLCp\\noUChYl/ADNOACICayHc2WeWPfxJ26BF0ahTzOX1fJsg++JDweCYCNN2WrrYcyA9o\\nXDU18IFh2dY2CvPL8G7ex5WEq9nYTASQzRfC899nTvUSTyECQQDZddRhqF9g6Zc9\\nvuSjwQf+dMztsvhLVPAPaSdgE4LMa4nE2iNC/sLq1uUEwrrrOKGaFB9IXeIU7hPW\\n2QmgJewxAkEAx65IjpesMEq+zE5qRPYkfxjdaa0gNBCfATEBGI4bTx37cKskf49W\\n2qFlombE9m9t/beYXVC++2W40i53ov+pLwJALRp0X4EFr1sjxGnIkHJkDxH4w0CA\\noVdPp1KfGR1S3sVbQNohwC6JDR5fR/p/vHP1iLituFvInaC3urMvfOkAsQJBAJg9\\n0gYdr+O16Vi95JoljNf2bkG3BJmNnp167ln5ZurgcieJ5K7464CPk3zJnBxEAvlx\\ndFKZULM98DcXxJFbGXMCQC2ZkPFgzMlRwYu4gake2ruOQR9N3HzLoau1jqDrgh6U\\nOw3ylw8RWPq4zmLkDPn83DFMBquYsg3yzBPi7PANBO4=\\n-----END RSA PRIVATE KEY-----\\n\",\n" +
        "    \"privateKeyPassword\": \"password\",\n" +
        "    \"requestSigned\": true,\n" +
        "    \"wantAssertionSigned\": true,\n" +
        "    \"wantAuthnRequestSigned\": false\n" +
        "}";

    String privateKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIICXAIBAAKBgQCpnqPQiDCfJY1hVaQUZG6Rs1Wd3FmP1EStN71hXeXOLog5nvpa\n" +
        "H45P3v79EGpaO06vH5qSu/xr6kQRBOA4h9OqXGS72BGQBH8jMNCoHqgJrIADQTHX\n" +
        "H85RYF38bH6Ycp18jch0KVmYwKeiaLNfMDngnAv6wMDONJz761GBtrG1/wIDAQAB\n" +
        "AoGAPjYeNSzOUICwcyO7E3Omji/tVgHso3EiYznPbvfGgrHUavXhMs7iHm9WrLCp\n" +
        "oUChYl/ADNOACICayHc2WeWPfxJ26BF0ahTzOX1fJsg++JDweCYCNN2WrrYcyA9o\n" +
        "XDU18IFh2dY2CvPL8G7ex5WEq9nYTASQzRfC899nTvUSTyECQQDZddRhqF9g6Zc9\n" +
        "vuSjwQf+dMztsvhLVPAPaSdgE4LMa4nE2iNC/sLq1uUEwrrrOKGaFB9IXeIU7hPW\n" +
        "2QmgJewxAkEAx65IjpesMEq+zE5qRPYkfxjdaa0gNBCfATEBGI4bTx37cKskf49W\n" +
        "2qFlombE9m9t/beYXVC++2W40i53ov+pLwJALRp0X4EFr1sjxGnIkHJkDxH4w0CA\n" +
        "oVdPp1KfGR1S3sVbQNohwC6JDR5fR/p/vHP1iLituFvInaC3urMvfOkAsQJBAJg9\n" +
        "0gYdr+O16Vi95JoljNf2bkG3BJmNnp167ln5ZurgcieJ5K7464CPk3zJnBxEAvlx\n" +
        "dFKZULM98DcXxJFbGXMCQC2ZkPFgzMlRwYu4gake2ruOQR9N3HzLoau1jqDrgh6U\n" +
        "Ow3ylw8RWPq4zmLkDPn83DFMBquYsg3yzBPi7PANBO4=\n" +
        "-----END RSA PRIVATE KEY-----\n";
    String passphrase = "password";

    String certificate = "-----BEGIN CERTIFICATE-----\n" +
        "MIID4zCCA0ygAwIBAgIJAJdmwmBdhEydMA0GCSqGSIb3DQEBBQUAMIGoMQswCQYD\n" +
        "VQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xJzAl\n" +
        "BgNVBAoTHkNsb3VkIEZvdW5kcnkgRm91bmRhdGlvbiwgSW5jLjEMMAoGA1UECxMD\n" +
        "VUFBMRIwEAYDVQQDEwlsb2NhbGhvc3QxKTAnBgkqhkiG9w0BCQEWGmNmLWlkZW50\n" +
        "aXR5LWVuZ0BwaXZvdGFsLmlvMB4XDTE2MDIxNjIyMTMzN1oXDTE2MDMxNzIyMTMz\n" +
        "N1owgagxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZy\n" +
        "YW5jaXNjbzEnMCUGA1UEChMeQ2xvdWQgRm91bmRyeSBGb3VuZGF0aW9uLCBJbmMu\n" +
        "MQwwCgYDVQQLEwNVQUExEjAQBgNVBAMTCWxvY2FsaG9zdDEpMCcGCSqGSIb3DQEJ\n" +
        "ARYaY2YtaWRlbnRpdHktZW5nQHBpdm90YWwuaW8wgZ8wDQYJKoZIhvcNAQEBBQAD\n" +
        "gY0AMIGJAoGBAKmeo9CIMJ8ljWFVpBRkbpGzVZ3cWY/URK03vWFd5c4uiDme+lof\n" +
        "jk/e/v0Qalo7Tq8fmpK7/GvqRBEE4DiH06pcZLvYEZAEfyMw0KgeqAmsgANBMdcf\n" +
        "zlFgXfxsfphynXyNyHQpWZjAp6Jos18wOeCcC/rAwM40nPvrUYG2sbX/AgMBAAGj\n" +
        "ggERMIIBDTAdBgNVHQ4EFgQUdiixDfiZ61ljk7J/uUYcay26n5swgd0GA1UdIwSB\n" +
        "1TCB0oAUdiixDfiZ61ljk7J/uUYcay26n5uhga6kgaswgagxCzAJBgNVBAYTAlVT\n" +
        "MQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEnMCUGA1UEChMe\n" +
        "Q2xvdWQgRm91bmRyeSBGb3VuZGF0aW9uLCBJbmMuMQwwCgYDVQQLEwNVQUExEjAQ\n" +
        "BgNVBAMTCWxvY2FsaG9zdDEpMCcGCSqGSIb3DQEJARYaY2YtaWRlbnRpdHktZW5n\n" +
        "QHBpdm90YWwuaW+CCQCXZsJgXYRMnTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB\n" +
        "BQUAA4GBAAPf/SPl/LuVYrl0HDUU8YDR3N7Fi4OjhF3+n+uBYRhO+9IbQ/t1sC1p\n" +
        "enWhiAfyZtgFv2OmjvtFyty9YqHhIPAg9Ceod37Q7HNSG04vbYHNJ6XhGUzacMj8\n" +
        "hQ1ZzQBv+CaKWZarBIql/TsxtpvvXhaE4QqR4NvUDnESHtxefriv\n" +
        "-----END CERTIFICATE-----\n";

    SamlConfig config;

    @Before
    public void setUp() {
        config = new SamlConfig();
    }

    @Test
    public void testIsRequestSigned() {
        assertTrue(config.isRequestSigned());
    }

    @Test
    public void legacy_key_is_part_of_map() {
        config.setPrivateKey(privateKey);
        config.setPrivateKeyPassword(passphrase);
        config.setCertificate(certificate);
        Map<String, SamlKey> keys = config.getKeys();
        assertEquals(1, keys.size());
        assertNotNull(keys.get(LEGACY_KEY_ID));
        assertEquals(privateKey, keys.get(LEGACY_KEY_ID).getKey());
        assertEquals(passphrase, keys.get(LEGACY_KEY_ID).getPassphrase());
        assertEquals(certificate, keys.get(LEGACY_KEY_ID).getCertificate());
    }

    @Test
    public void addActiveKey() {
        SamlKey key = new SamlKey(privateKey, passphrase, certificate);
        String keyId = "testKeyId";
        config.addAndActivateKey(keyId, key);
        Map<String, SamlKey> keys = config.getKeys();
        assertNotNull(keys);
        assertEquals(1, keys.size());
        assertEquals(keyId, config.getActiveKeyId());
        assertNotNull(keys.get(keyId));
        assertEquals(privateKey, keys.get(keyId).getKey());
        assertEquals(passphrase, keys.get(keyId).getPassphrase());
        assertEquals(certificate, keys.get(keyId).getCertificate());
    }

    @Test
    public void addNonActive() {
        addActiveKey();
        SamlKey key = new SamlKey(privateKey, passphrase, certificate);
        String keyId = "nonActiveKeyId";
        config.addKey(keyId, key);
        Map<String, SamlKey> keys = config.getKeys();
        assertNotNull(keys);
        assertEquals(2, keys.size());
        assertNotEquals(keyId, config.getActiveKeyId());
        assertNotNull(keys.get(keyId));
        assertEquals(privateKey, keys.get(keyId).getKey());
        assertEquals(passphrase, keys.get(keyId).getPassphrase());
        assertEquals(certificate, keys.get(keyId).getCertificate());
    }

    @Test
    public void map_is_not_null_by_default() {
        Map<String, SamlKey> keys = config.getKeys();
        assertNotNull(keys);
        assertEquals(0, keys.size());
        assertNull(config.getActiveKeyId());
    }

    @Test
    public void testIsWantAssertionSigned() {
        assertTrue(config.isWantAssertionSigned());
    }

    @Test
    public void testSetKeyAndCert() {
        config.setPrivateKey(privateKey);
        config.setPrivateKeyPassword(passphrase);
        config.setCertificate(certificate);
        assertEquals(privateKey, config.getPrivateKey());
        assertEquals(passphrase, config.getPrivateKeyPassword());
    }

    @Test
    public void read_old_json_works() {
        read_json(oldJson);
        assertEquals(privateKey, config.getPrivateKey());
        assertEquals(passphrase, config.getPrivateKeyPassword());
        assertEquals(certificate, config.getCertificate());
    }

    public void read_json(String json) {
        config = JsonUtils.readValue(json, SamlConfig.class);
    }

    @Test
    public void to_json_ignores_legacy_values() {
        read_json(oldJson);
        String json = JsonUtils.writeValueAsString(config);
        read_json(json);
        assertEquals(privateKey, config.getPrivateKey());
        assertEquals(passphrase, config.getPrivateKeyPassword());
        assertEquals(certificate, config.getCertificate());
    }

    @Test
    public void keys_are_not_modifiable() {
        read_json(oldJson);
        exception.expect(UnsupportedOperationException.class);
        config.getKeys().clear();
    }

    @Test
    public void can_clear_keys() {
        read_json(oldJson);
        assertEquals(1, config.getKeys().size());
        assertNotNull(config.getActiveKeyId());
        config.setKeys(EMPTY_MAP);
        assertEquals(0, config.getKeys().size());
        assertNull(config.getActiveKeyId());
    }




}
