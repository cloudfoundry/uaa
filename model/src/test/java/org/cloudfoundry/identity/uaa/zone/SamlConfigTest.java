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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.cloudfoundry.identity.uaa.zone.SamlConfig.LEGACY_KEY_ID;

class SamlConfigTest {

    String oldJson = """
            {
                "assertionSigned": true,
                "assertionTimeToLiveSeconds": 600,
                "certificate": "-----BEGIN CERTIFICATE-----\\nMIID4zCCA0ygAwIBAgIJAJdmwmBdhEydMA0GCSqGSIb3DQEBBQUAMIGoMQswCQYD\\nVQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xJzAl\\nBgNVBAoTHkNsb3VkIEZvdW5kcnkgRm91bmRhdGlvbiwgSW5jLjEMMAoGA1UECxMD\\nVUFBMRIwEAYDVQQDEwlsb2NhbGhvc3QxKTAnBgkqhkiG9w0BCQEWGmNmLWlkZW50\\naXR5LWVuZ0BwaXZvdGFsLmlvMB4XDTE2MDIxNjIyMTMzN1oXDTE2MDMxNzIyMTMz\\nN1owgagxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZy\\nYW5jaXNjbzEnMCUGA1UEChMeQ2xvdWQgRm91bmRyeSBGb3VuZGF0aW9uLCBJbmMu\\nMQwwCgYDVQQLEwNVQUExEjAQBgNVBAMTCWxvY2FsaG9zdDEpMCcGCSqGSIb3DQEJ\\nARYaY2YtaWRlbnRpdHktZW5nQHBpdm90YWwuaW8wgZ8wDQYJKoZIhvcNAQEBBQAD\\ngY0AMIGJAoGBAKmeo9CIMJ8ljWFVpBRkbpGzVZ3cWY/URK03vWFd5c4uiDme+lof\\njk/e/v0Qalo7Tq8fmpK7/GvqRBEE4DiH06pcZLvYEZAEfyMw0KgeqAmsgANBMdcf\\nzlFgXfxsfphynXyNyHQpWZjAp6Jos18wOeCcC/rAwM40nPvrUYG2sbX/AgMBAAGj\\nggERMIIBDTAdBgNVHQ4EFgQUdiixDfiZ61ljk7J/uUYcay26n5swgd0GA1UdIwSB\\n1TCB0oAUdiixDfiZ61ljk7J/uUYcay26n5uhga6kgaswgagxCzAJBgNVBAYTAlVT\\nMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEnMCUGA1UEChMe\\nQ2xvdWQgRm91bmRyeSBGb3VuZGF0aW9uLCBJbmMuMQwwCgYDVQQLEwNVQUExEjAQ\\nBgNVBAMTCWxvY2FsaG9zdDEpMCcGCSqGSIb3DQEJARYaY2YtaWRlbnRpdHktZW5n\\nQHBpdm90YWwuaW+CCQCXZsJgXYRMnTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB\\nBQUAA4GBAAPf/SPl/LuVYrl0HDUU8YDR3N7Fi4OjhF3+n+uBYRhO+9IbQ/t1sC1p\\nenWhiAfyZtgFv2OmjvtFyty9YqHhIPAg9Ceod37Q7HNSG04vbYHNJ6XhGUzacMj8\\nhQ1ZzQBv+CaKWZarBIql/TsxtpvvXhaE4QqR4NvUDnESHtxefriv\\n-----END CERTIFICATE-----\\n",
                "privateKey": "-----BEGIN RSA PRIVATE KEY-----\\nMIICXAIBAAKBgQCpnqPQiDCfJY1hVaQUZG6Rs1Wd3FmP1EStN71hXeXOLog5nvpa\\nH45P3v79EGpaO06vH5qSu/xr6kQRBOA4h9OqXGS72BGQBH8jMNCoHqgJrIADQTHX\\nH85RYF38bH6Ycp18jch0KVmYwKeiaLNfMDngnAv6wMDONJz761GBtrG1/wIDAQAB\\nAoGAPjYeNSzOUICwcyO7E3Omji/tVgHso3EiYznPbvfGgrHUavXhMs7iHm9WrLCp\\noUChYl/ADNOACICayHc2WeWPfxJ26BF0ahTzOX1fJsg++JDweCYCNN2WrrYcyA9o\\nXDU18IFh2dY2CvPL8G7ex5WEq9nYTASQzRfC899nTvUSTyECQQDZddRhqF9g6Zc9\\nvuSjwQf+dMztsvhLVPAPaSdgE4LMa4nE2iNC/sLq1uUEwrrrOKGaFB9IXeIU7hPW\\n2QmgJewxAkEAx65IjpesMEq+zE5qRPYkfxjdaa0gNBCfATEBGI4bTx37cKskf49W\\n2qFlombE9m9t/beYXVC++2W40i53ov+pLwJALRp0X4EFr1sjxGnIkHJkDxH4w0CA\\noVdPp1KfGR1S3sVbQNohwC6JDR5fR/p/vHP1iLituFvInaC3urMvfOkAsQJBAJg9\\n0gYdr+O16Vi95JoljNf2bkG3BJmNnp167ln5ZurgcieJ5K7464CPk3zJnBxEAvlx\\ndFKZULM98DcXxJFbGXMCQC2ZkPFgzMlRwYu4gake2ruOQR9N3HzLoau1jqDrgh6U\\nOw3ylw8RWPq4zmLkDPn83DFMBquYsg3yzBPi7PANBO4=\\n-----END RSA PRIVATE KEY-----\\n",
                "privateKeyPassword": "password",
                "requestSigned": true,
                "wantAssertionSigned": true,
                "wantAuthnRequestSigned": false
            }\
            """;

    String privateKey = """
            -----BEGIN RSA PRIVATE KEY-----
            MIICXAIBAAKBgQCpnqPQiDCfJY1hVaQUZG6Rs1Wd3FmP1EStN71hXeXOLog5nvpa
            H45P3v79EGpaO06vH5qSu/xr6kQRBOA4h9OqXGS72BGQBH8jMNCoHqgJrIADQTHX
            H85RYF38bH6Ycp18jch0KVmYwKeiaLNfMDngnAv6wMDONJz761GBtrG1/wIDAQAB
            AoGAPjYeNSzOUICwcyO7E3Omji/tVgHso3EiYznPbvfGgrHUavXhMs7iHm9WrLCp
            oUChYl/ADNOACICayHc2WeWPfxJ26BF0ahTzOX1fJsg++JDweCYCNN2WrrYcyA9o
            XDU18IFh2dY2CvPL8G7ex5WEq9nYTASQzRfC899nTvUSTyECQQDZddRhqF9g6Zc9
            vuSjwQf+dMztsvhLVPAPaSdgE4LMa4nE2iNC/sLq1uUEwrrrOKGaFB9IXeIU7hPW
            2QmgJewxAkEAx65IjpesMEq+zE5qRPYkfxjdaa0gNBCfATEBGI4bTx37cKskf49W
            2qFlombE9m9t/beYXVC++2W40i53ov+pLwJALRp0X4EFr1sjxGnIkHJkDxH4w0CA
            oVdPp1KfGR1S3sVbQNohwC6JDR5fR/p/vHP1iLituFvInaC3urMvfOkAsQJBAJg9
            0gYdr+O16Vi95JoljNf2bkG3BJmNnp167ln5ZurgcieJ5K7464CPk3zJnBxEAvlx
            dFKZULM98DcXxJFbGXMCQC2ZkPFgzMlRwYu4gake2ruOQR9N3HzLoau1jqDrgh6U
            Ow3ylw8RWPq4zmLkDPn83DFMBquYsg3yzBPi7PANBO4=
            -----END RSA PRIVATE KEY-----
            """;
    String passphrase = "password";

    String certificate = """
            -----BEGIN CERTIFICATE-----
            MIID4zCCA0ygAwIBAgIJAJdmwmBdhEydMA0GCSqGSIb3DQEBBQUAMIGoMQswCQYD
            VQQGEwJVUzELMAkGA1UECBMCQ0ExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xJzAl
            BgNVBAoTHkNsb3VkIEZvdW5kcnkgRm91bmRhdGlvbiwgSW5jLjEMMAoGA1UECxMD
            VUFBMRIwEAYDVQQDEwlsb2NhbGhvc3QxKTAnBgkqhkiG9w0BCQEWGmNmLWlkZW50
            aXR5LWVuZ0BwaXZvdGFsLmlvMB4XDTE2MDIxNjIyMTMzN1oXDTE2MDMxNzIyMTMz
            N1owgagxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZy
            YW5jaXNjbzEnMCUGA1UEChMeQ2xvdWQgRm91bmRyeSBGb3VuZGF0aW9uLCBJbmMu
            MQwwCgYDVQQLEwNVQUExEjAQBgNVBAMTCWxvY2FsaG9zdDEpMCcGCSqGSIb3DQEJ
            ARYaY2YtaWRlbnRpdHktZW5nQHBpdm90YWwuaW8wgZ8wDQYJKoZIhvcNAQEBBQAD
            gY0AMIGJAoGBAKmeo9CIMJ8ljWFVpBRkbpGzVZ3cWY/URK03vWFd5c4uiDme+lof
            jk/e/v0Qalo7Tq8fmpK7/GvqRBEE4DiH06pcZLvYEZAEfyMw0KgeqAmsgANBMdcf
            zlFgXfxsfphynXyNyHQpWZjAp6Jos18wOeCcC/rAwM40nPvrUYG2sbX/AgMBAAGj
            ggERMIIBDTAdBgNVHQ4EFgQUdiixDfiZ61ljk7J/uUYcay26n5swgd0GA1UdIwSB
            1TCB0oAUdiixDfiZ61ljk7J/uUYcay26n5uhga6kgaswgagxCzAJBgNVBAYTAlVT
            MQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEnMCUGA1UEChMe
            Q2xvdWQgRm91bmRyeSBGb3VuZGF0aW9uLCBJbmMuMQwwCgYDVQQLEwNVQUExEjAQ
            BgNVBAMTCWxvY2FsaG9zdDEpMCcGCSqGSIb3DQEJARYaY2YtaWRlbnRpdHktZW5n
            QHBpdm90YWwuaW+CCQCXZsJgXYRMnTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEB
            BQUAA4GBAAPf/SPl/LuVYrl0HDUU8YDR3N7Fi4OjhF3+n+uBYRhO+9IbQ/t1sC1p
            enWhiAfyZtgFv2OmjvtFyty9YqHhIPAg9Ceod37Q7HNSG04vbYHNJ6XhGUzacMj8
            hQ1ZzQBv+CaKWZarBIql/TsxtpvvXhaE4QqR4NvUDnESHtxefriv
            -----END CERTIFICATE-----
            """;

    SamlConfig config;

    @BeforeEach
    void setUp() {
        config = new SamlConfig();
    }

    @Test
    void isRequestSigned() {
        assertThat(config.isRequestSigned()).isTrue();
    }

    @Test
    void legacy_key_is_part_of_map() {
        config.setPrivateKey(privateKey);
        config.setPrivateKeyPassword(passphrase);
        config.setCertificate(certificate);
        Map<String, SamlKey> keys = config.getKeys();
        assertThat(keys).containsOnlyKeys(LEGACY_KEY_ID);
        assertThat(keys.get(LEGACY_KEY_ID).getKey()).isEqualTo(privateKey);
        assertThat(keys.get(LEGACY_KEY_ID).getPassphrase()).isEqualTo(passphrase);
        assertThat(keys.get(LEGACY_KEY_ID).getCertificate()).isEqualTo(certificate);
    }

    @Test
    void addActiveKey() {
        SamlKey key = new SamlKey(privateKey, passphrase, certificate);
        String keyId = "testKeyId";
        config.addAndActivateKey(keyId, key);
        Map<String, SamlKey> keys = config.getKeys();
        assertThat(keys).hasSize(1)
                .containsKey(keyId);
        assertThat(config.getActiveKeyId()).isEqualTo(keyId);
        assertThat(keys.get(keyId)).returns(privateKey, SamlKey::getKey)
                .returns(passphrase, SamlKey::getPassphrase)
                .returns(certificate, SamlKey::getCertificate);
        assertThat(config.getActiveKey()).isSameAs(keys.get(keyId));
        assertThat(config.getKeyList()).hasSize(1).containsExactly(key);
    }

    @Test
    void addNonActive() {
        addActiveKey();
        SamlKey key = new SamlKey(privateKey, passphrase, certificate);
        String keyId = "nonActiveKeyId";
        config.addKey(keyId, key);
        Map<String, SamlKey> keys = config.getKeys();
        assertThat(keys).hasSize(2)
                .containsKey(keyId);
        assertThat(config.getActiveKeyId()).isNotEqualTo(keyId);
        assertThat(keys.get(keyId)).returns(privateKey, SamlKey::getKey)
                .returns(passphrase, SamlKey::getPassphrase)
                .returns(certificate, SamlKey::getCertificate);
    }

    @Test
    void getKeyList() {
        // Default is empty
        assertThat(config.getKeyList()).isEmpty();

        // Add active key, should only have that key
        addActiveKey();
        SamlKey activeKey = config.getActiveKey();
        assertThat(config.getKeyList()).containsExactly(activeKey);

        // Add another key, should have both keys
        SamlKey nonActiveKey = new SamlKey(privateKey, passphrase, certificate);
        String nonActiveKeyId = "nonActiveKeyId";
        config.addKey(nonActiveKeyId, nonActiveKey);
        assertThat(config.getKeyList()).containsExactly(activeKey, nonActiveKey);

        // add another active key, should have the new key first
        SamlKey otherActiveKey = new SamlKey(privateKey, passphrase, certificate);
        config.addAndActivateKey("anotherActiveKeyId", otherActiveKey);
        assertThat(config.getKeyList()).hasSize(3).first().isSameAs(otherActiveKey);

        // remove the non-active key, should have other 2 keys
        config.removeKey(nonActiveKeyId);
        assertThat(config.getKeyList()).containsExactly(otherActiveKey, activeKey);

        // drop the current active key, should have only the remaining key... even though it is not active
        config.removeKey("anotherActiveKeyId");
        assertThat(config.getActiveKey()).isNull();
        assertThat(config.getKeys()).hasSize(1);
        assertThat(config.getKeyList()).containsExactly(activeKey);
    }

    @Test
    void map_is_not_null_by_default() {
        Map<String, SamlKey> keys = config.getKeys();
        assertThat(keys).isEmpty();
        assertThat(config.getActiveKeyId()).isNull();
    }

    @Test
    void isWantAssertionSigned() {
        assertThat(config.isWantAssertionSigned()).isTrue();
    }

    @Test
    void setKeyAndCert() {
        // Default values are null
        assertThat(config).returns(null, SamlConfig::getPrivateKey)
                .returns(null, SamlConfig::getPrivateKeyPassword)
                .returns(null, SamlConfig::getCertificate)
                .extracting(SamlConfig::getActiveKey)
                .isNull();

        // Set values to null, does not create a key
        config.setPrivateKey(null);
        config.setPrivateKeyPassword(null);
        config.setCertificate(null);
        assertThat(config).returns(null, SamlConfig::getPrivateKey)
                .returns(null, SamlConfig::getPrivateKeyPassword)
                .returns(null, SamlConfig::getCertificate)
                .extracting(SamlConfig::getActiveKey)
                .isNull();

        // Set values to non-null, creates a key object
        config.setPrivateKey(privateKey);
        config.setPrivateKeyPassword(passphrase);
        config.setCertificate(certificate);
        assertThat(config).returns(privateKey, SamlConfig::getPrivateKey)
                .returns(passphrase, SamlConfig::getPrivateKeyPassword)
                .returns(certificate, SamlConfig::getCertificate)
                .extracting(SamlConfig::getActiveKey)
                .isNotNull()
                .returns(privateKey, SamlKey::getKey)
                .returns(certificate, SamlKey::getCertificate)
                .returns(passphrase, SamlKey::getPassphrase);

        // Set values to null, retains the key object with nulls
        config.setPrivateKey(null);
        config.setPrivateKeyPassword(null);
        config.setCertificate(null);
        assertThat(config).returns(null, SamlConfig::getPrivateKey)
                .returns(null, SamlConfig::getPrivateKeyPassword)
                .returns(null, SamlConfig::getCertificate)
                .extracting(SamlConfig::getActiveKey)
                .isNotNull()
                .returns(null, SamlKey::getKey)
                .returns(null, SamlKey::getCertificate)
                .returns(null, SamlKey::getPassphrase);
    }

    @Test
    void read_old_json_works() {
        read_json(oldJson);
        assertThat(config).returns(privateKey, SamlConfig::getPrivateKey)
                .returns(passphrase, SamlConfig::getPrivateKeyPassword)
                .returns(certificate, SamlConfig::getCertificate);
    }

    public void read_json(String json) {
        config = JsonUtils.readValue(json, SamlConfig.class);
    }

    @Test
    void to_json_ignores_legacy_values() {
        read_json(oldJson);
        String json = JsonUtils.writeValueAsString(config);
        read_json(json);
        assertThat(config).returns(privateKey, SamlConfig::getPrivateKey)
                .returns(passphrase, SamlConfig::getPrivateKeyPassword)
                .returns(certificate, SamlConfig::getCertificate);
    }

    @Test
    void keys_are_not_modifiable() {
        read_json(oldJson);
        Map<String, SamlKey> keys = config.getKeys();
        assertThatThrownBy(keys::clear).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void can_clear_keys() {
        read_json(oldJson);
        assertThat(config.getKeys()).hasSize(1);
        assertThat(config.getActiveKeyId()).isNotNull();
        assertThat(config.getActiveKey()).isNotNull();
        config.setKeys(Collections.emptyMap());
        assertThat(config.getKeys()).isEmpty();
        assertThat(config.getActiveKeyId()).isNull();
        assertThat(config.getActiveKey()).isNull();
    }
}