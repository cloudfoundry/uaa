/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.util.StringUtils;

import java.util.LinkedList;
import java.util.List;

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
        signerProvider.setVerifierKey("testkey");

        assertNotNull(signerProvider.getSigner());
        assertNotNull(signerProvider.getVerifier());

        byte[] signedValue = signerProvider.getSigner().sign("joel".getBytes());
        signerProvider.getVerifier().verify("joel".getBytes(), signedValue);
    }

    @Test(expected = IllegalArgumentException.class)
    public void accidentallySetPrivateKeyAsVerifier() throws Exception {
        String rsaKey = "-----BEGIN RSA PRIVATE KEY-----\n"
                        + "MIIBywIBAAJhAOTeb4AZ+NwOtPh+ynIgGqa6UWNVe6JyJi+loPmPZdpHtzoqubnC \n"
                        + "wEs6JSiSZ3rButEAw8ymgLV6iBY02hdjsl3h5Z0NWaxx8dzMZfXe4EpfB04ISoqq\n"
                        + "hZCxchvuSDP4eQIDAQABAmEAqUuYsuuDWFRQrZgsbGsvC7G6zn3HLIy/jnM4NiJK\n"
                        + "t0JhWNeN9skGsR7bqb1Sak2uWqW8ZqnqgAC32gxFRYHTavJEk6LTaHWovwDEhPqc\n"
                        + "Zs+vXd6tZojJQ35chR/slUEBAjEA/sAd1oFLWb6PHkaz7r2NllwUBTvXL4VcMWTS\n"
                        + "pN+5cU41i9fsZcHw6yZEl+ZCicDxAjEA5f3R+Bj42htNI7eylebew1+sUnFv1xT8\n"
                        + "jlzxSzwVkoZo+vef7OD6OcFLeInAHzAJAjEAs6izolK+3ETa1CRSwz0lPHQlnmdM\n"
                        + "Y/QuR5tuPt6U/saEVuJpkn4LNRtg5qt6I4JRAjAgFRYTG7irBB/wmZFp47izXEc3\n"
                        + "gOdvA1hvq3tlWU5REDrYt24xpviA0fvrJpwMPbECMAKDKdiDi6Q4/iBkkzNMefA8\n"
                        + "7HX27b9LR33don/1u/yvzMUo+lrRdKAFJ+9GPE9XFA== \n" + "-----END RSA PRIVATE KEY-----";
        signerProvider.setVerifierKey(rsaKey);
    }

    @Test
    public void testSignedProviderAsymmetricKeys() throws Exception {
        SignerProvider signerProvider = new SignerProvider();
        signerProvider.setSigningKey("-----BEGIN RSA PRIVATE KEY-----\n" +
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
                        "-----END RSA PRIVATE KEY-----");
        signerProvider.setVerifierKey("-----BEGIN RSA PUBLIC KEY-----\n" +
                        "MIGJAoGBAMStmxljvRABrtZ0MPp46/dEsEDgjknTNk6JczOgUHnKHrirSyYRI21X\n" +
                        "ilrI5gTlOcfFaMyjTLuAOwaMjWiYAbrCB/Knrcj1ZwtfsUMvJ57jd8bn5v2uih+i\n" +
                        "wv47MlJcRJK6WxP1jVfFIUUzlEy7gh724zj+LMosKwAqKCAyGcCZAgMBAAE=\n" +
                        "-----END RSA PUBLIC KEY-----");
        signerProvider.afterPropertiesSet();
        assertNotNull(signerProvider.getSigner());
        assertNotNull(signerProvider.getVerifier());

        byte[] signedValue = signerProvider.getSigner().sign("joel".getBytes());
        signerProvider.getVerifier().verify("joel".getBytes(), signedValue);
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

    @Test(expected = IllegalStateException.class)
    public void keysNotMatchingWithMacSigner() throws Exception {
        signerProvider.setSigningKey("aKey");
        signerProvider.setVerifierKey("someKey");
        signerProvider.afterPropertiesSet();
    }

    @Test(expected = IllegalStateException.class)
    public void keysNotSameWithMacSigner() throws Exception {
        signerProvider.setSigningKey("aKey");
        signerProvider.setVerifierKey(new String("aKey"));
        signerProvider.afterPropertiesSet();
    }

}
