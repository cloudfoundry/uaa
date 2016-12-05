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

import org.junit.Before;
import org.junit.Test;

import java.security.cert.CertificateException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class SamlConfigTest {

    SamlConfig config;

    @Before
    public void setUp() {
        config = new SamlConfig();
    }

    @Test
    public void testIsRequestSigned() throws Exception {
        assertTrue(config.isRequestSigned());

    }

    @Test
    public void testIsWantAssertionSigned() throws Exception {
        assertTrue(config.isWantAssertionSigned());
    }

    @Test
    public void testSetKeyAndCert() throws CertificateException {
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

        config.setPrivateKey(privateKey);
        config.setPrivateKeyPassword(passphrase);
        config.setCertificate(certificate);
        assertEquals(privateKey, config.getPrivateKey());
        assertEquals(passphrase, config.getPrivateKeyPassword());
    }
}
