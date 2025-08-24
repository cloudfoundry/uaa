/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.jwk.JWKParameterNames;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class SignatureVerifierTest {

    @Test
    void null_is_not_an_acceptable_key() {
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> new SignatureVerifier(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "-----BEGIN PUBLIC KEY----- MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMi4Z4FBfQEOdNYLmzxk YJvP02TSeapZMKMQo90JQRL07ttIKcDMP6pGcirOGSQWWBBpvdo5EnVOiNzViu9J CJP2IWbHJ4sRe0S1dySYdBRVV/ZkgWOrj7Cr2yT0ZVvCCzH7NAWmlA6LUV19Mnp+ ugeGoxK+fsk8SRLS/Z9JdyxgOb3tPxdDas3MZweMZ6HqujoAAG9NASBGjFNXbhMc krEfecwm3OJzsjGFxhqXRqkTsGEHvzETMxfvSkTkldOzmErnjpwyoOPLrXcWIs1w vdXHakfVHSvyb3T4gm3ZfOOoUf6lrd2w1pF/PkA88NkjN2+W9fQmbUzNgVjEQiXo 4wIDAQAB -----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAn+pxzfKFDleFHY5Tc65Y\nMk3ODla+YWw+2TWchZI4qgGjrRwthYp1Ei+rMFDE8cdTHjIEHRPu+rhpvFOaNs1c\nhmPPlqk0ctxWkx6jwdz4Za5NsJjn6Os6RTYUBvTZpac5g+d33c8z1ZLIh5EO3RzZ\nrWsBEebbPAps4l2uoXYOyyU7IEMaCAlCEN8B9nvLnmNOm95ZMgvKCGnIk2ruptt9\n3eM/vAEVHdgBosslMJ7VWnpvTBQcbQJ4e5O6rn6cTnK/SA3n+p6/3+ElLV7tuMf9\nGi8reWS7SjK7hsRj15iGP+Mpir5AKInrveQtgFcTmmelyAvjTo30XNebQ9uwbIAo\nqcKjar/QVdb4fyRTMBC+Qc5X0ckXUQHOhYdVpo2rCAYPRjknFcyC3ijayoCH3oeF\nhb3MUPRLX+ydqPhN17j3ONnwfdGBbHSBBBQ0C6VPnwJh7I13dXQPedFVUfEXrVfg\niiByM70QoVPGp9nA0iOIMDKY9yKlRXAHImHLwWpc9Wuj7OwZ0VbboHLQlVCCmKab\nQMV3O2RM3iZH0u2wxjyB5MjCJq/hiHvAbPGzIe0hdv6VkZ96Zmen7AKqewSc8zmK\nqrxv/xdwtk5ZG88WjkOIUaxVuxr2KbixlKp8VU1Hqi11FMlp3suXivOlXBonqHtV\nEBwq7u1C9VPi0EFuSOvgTMMCAwEAAQ==\n-----END PUBLIC KEY-----",
            "-----BEGIN PUBLIC KEY-----MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAn+pxzfKFDleFHY5Tc65YMk3ODla+YWw+2TWchZI4qgGjrRwthYp1Ei+rMFDE8cdTHjIEHRPu+rhpvFOaNs1chmPPlqk0ctxWkx6jwdz4Za5NsJjn6Os6RTYUBvTZpac5g+d33c8z1ZLIh5EO3RzZrWsBEebbPAps4l2uoXYOyyU7IEMaCAlCEN8B9nvLnmNOm95ZMgvKCGnIk2ruptt93eM/vAEVHdgBosslMJ7VWnpvTBQcbQJ4e5O6rn6cTnK/SA3n+p6/3+ElLV7tuMf9Gi8reWS7SjK7hsRj15iGP+Mpir5AKInrveQtgFcTmmelyAvjTo30XNebQ9uwbIAoqcKjar/QVdb4fyRTMBC+Qc5X0ckXUQHOhYdVpo2rCAYPRjknFcyC3ijayoCH3oeFhb3MUPRLX+ydqPhN17j3ONnwfdGBbHSBBBQ0C6VPnwJh7I13dXQPedFVUfEXrVfgiiByM70QoVPGp9nA0iOIMDKY9yKlRXAHImHLwWpc9Wuj7OwZ0VbboHLQlVCCmKabQMV3O2RM3iZH0u2wxjyB5MjCJq/hiHvAbPGzIe0hdv6VkZ96Zmen7AKqewSc8zmKqrxv/xdwtk5ZG88WjkOIUaxVuxr2KbixlKp8VU1Hqi11FMlp3suXivOlXBonqHtVEBwq7u1C9VPi0EFuSOvgTMMCAwEAAQ==-----END PUBLIC KEY-----",
            "-----BEGIN CERTIFICATE-----MIIEEzCCAvugAwIBAgIJAIc1qzLrv+5nMA0GCSqGSIb3DQEBCwUAMIGfMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ08xFDASBgNVBAcMC0Nhc3RsZSBSb2NrMRwwGgYDVQQKDBNTYW1sIFRlc3RpbmcgU2VydmVyMQswCQYDVQQLDAJJVDEgMB4GA1UEAwwXc2ltcGxlc2FtbHBocC5jZmFwcHMuaW8xIDAeBgkqhkiG9w0BCQEWEWZoYW5pa0BwaXZvdGFsLmlvMB4XDTE1MDIyMzIyNDUwM1oXDTI1MDIyMjIyNDUwM1owgZ8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDTzEUMBIGA1UEBwwLQ2FzdGxlIFJvY2sxHDAaBgNVBAoME1NhbWwgVGVzdGluZyBTZXJ2ZXIxCzAJBgNVBAsMAklUMSAwHgYDVQQDDBdzaW1wbGVzYW1scGhwLmNmYXBwcy5pbzEgMB4GCSqGSIb3DQEJARYRZmhhbmlrQHBpdm90YWwuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4cn62E1xLqpN34PmbrKBbkOXFjzWgJ9b+pXuaRft6A339uuIQeoeH5qeSKRVTl32L0gdz2ZivLwZXW+cqvftVW1tvEHvzJFyxeTW3fCUeCQsebLnA2qRa07RkxTo6Nf244mWWRDodcoHEfDUSbxfTZ6IExSojSIU2RnD6WllYWFdD1GFpBJOmQB8rAc8wJIBdHFdQnX8Ttl7hZ6rtgqEYMzYVMuJ2F2r1HSU1zSAvwpdYP6rRGFRJEfdA9mm3WKfNLSc5cljz0X/TXy0vVlAV95l9qcfFzPmrkNIst9FZSwpvB49LyAVke04FQPPwLgVH4gphiJH3jvZ7I+J5lS8VAgMBAAGjUDBOMB0GA1UdDgQWBBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAfBgNVHSMEGDAWgBTTyP6Cc5HlBJ5+ucVCwGc5ogKNGzAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAvMS4EQeP/ipV4jOG5lO6/tYCb/iJeAduOnRhkJk0DbX329lDLZhTTL/x/w/9muCVcvLrzEp6PN+VWfw5E5FWtZN0yhGtP9R+vZnrV+oc2zGD+no1/ySFOe3EiJCO5dehxKjYEmBRv5sU/LZFKZpozKN/BMEa6CqLuxbzb7ykxVr7EVFXwltPxzE9TmL9OACNNyF5eJHWMRMllarUvkcXlh4pux4ks9e6zV9DQBy2zds9f1I3qxg0eX6JnGrXi/ZiCT+lJgVe3ZFXiejiLAiKB04sXW3ti0LW3lx13Y1YlQ4/tlpgTgfIJxKV6nyPiLoK0nywbMd+vpAirDt2Oc+hk-----END CERTIFICATE-----"
    })
    void getRsaPublicKeyFromConfig(String value) {
        HashMap key = new HashMap();
        key.put(JWKParameterNames.KEY_TYPE, "RSA");
        key.put("value", value);
        JsonWebKey jsonWebKey = new JsonWebKey(key);
        SignatureVerifier cs = new SignatureVerifier(jsonWebKey);
        assertThat(cs).isNotNull();
        assertThat(cs.algorithm()).isEqualTo("RS256");
        assertThat(cs.getJwkSet().size()).isOne();
        assertThat(cs.getJwkSet().getKeys().getFirst().getAlgorithm()).isNull();
    }

    @Test
    void getHmacKeyFromConfig() {
        HashMap key = new HashMap();
        key.put(JWKParameterNames.KEY_TYPE, "MAC");
        key.put(JWKParameterNames.KEY_ID, "legacy-token-key");
        key.put("value", "tokenKey");
        JsonWebKey jsonWebKey = new JsonWebKey(key);
        SignatureVerifier cs = new SignatureVerifier(jsonWebKey);
        assertThat(cs).isNotNull();
        assertThat(cs.algorithm()).isEqualTo("HS256");
        assertThat(cs.getJwkSet().size()).isOne();
        assertThat(cs.getJwkSet().getKeys().getFirst().getAlgorithm().getName()).isEqualTo("HS256");
    }

    @Test
    void getRsaPublicKeyFromConfigInvalid() {
        HashMap key = new HashMap();
        key.put(JWKParameterNames.KEY_TYPE, "RSA");
        key.put("value", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMi4Z4");
        JsonWebKey jsonWebKey = new JsonWebKey(key);
        assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(() -> new SignatureVerifier(jsonWebKey));
    }
}
