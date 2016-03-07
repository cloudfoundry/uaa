/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.SignerProvider;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.StringUtils;

import java.util.LinkedList;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

/**
 *
 * @author Joel D'sa
 *
 */
public class SignerProviderTests {

    private SignerProvider signerProvider = new SignerProvider();

    @Test
    public void testSignedProviderSymmetricKeys() {
        signerProvider.setSigningKey("testkey");

        assertNotNull(signerProvider.getSigner());
        assertNotNull(signerProvider.getVerifier());

        byte[] signedValue = signerProvider.getSigner().sign("joel".getBytes());
        signerProvider.getVerifier().verify("joel".getBytes(), signedValue);
    }

    @Test
    public void testSignedProviderAsymmetricKeys() throws Exception {
        SignerProvider signerProvider = new SignerProvider();
        String signingKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
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
        signerProvider.setSigningKey(signingKey);
        assertNotNull(signerProvider.getSigner());
        assertNotNull(signerProvider.getVerifier());

        byte[] signedValue = signerProvider.getSigner().sign("joel".getBytes());
        signerProvider.getVerifier().verify("joel".getBytes(), signedValue);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testNullSigningKey() {
        new SignerProvider(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testEmptySigningKey() {
        new SignerProvider(null);
    }

    @Test
    public void testRevocationHash() throws Exception {
        List<String> salts = new LinkedList<>();
        for (int i=0; i<3; i++) {
            salts.add(new RandomValueStringGenerator().generate());
        }
        String hash1 = signerProvider.getRevocationHash(salts);
        String hash2 = signerProvider.getRevocationHash(salts);
        assertFalse("Hash 1 should not be empty",StringUtils.isEmpty(hash1));
        assertFalse("Hash 2 should not be empty", StringUtils.isEmpty(hash2));
        assertEquals(hash1, hash2);
    }
}
