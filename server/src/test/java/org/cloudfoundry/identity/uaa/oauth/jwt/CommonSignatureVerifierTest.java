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
import org.junit.Test;

import java.util.HashMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

public class CommonSignatureVerifierTest {

    @Test(expected = IllegalArgumentException.class)
    public void null_is_not_an_acceptable_key() {
        new CommonSignatureVerifier(null);
    }

    @Test
    public void testGetRsaPublicKeyFromConfig() {
        HashMap key = new HashMap();
        key.put(JWKParameterNames.KEY_TYPE, "RSA");
        key.put("value", "-----BEGIN PUBLIC KEY----- MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMi4Z4FBfQEOdNYLmzxk YJvP02TSeapZMKMQo90JQRL07ttIKcDMP6pGcirOGSQWWBBpvdo5EnVOiNzViu9J CJP2IWbHJ4sRe0S1dySYdBRVV/ZkgWOrj7Cr2yT0ZVvCCzH7NAWmlA6LUV19Mnp+ ugeGoxK+fsk8SRLS/Z9JdyxgOb3tPxdDas3MZweMZ6HqujoAAG9NASBGjFNXbhMc krEfecwm3OJzsjGFxhqXRqkTsGEHvzETMxfvSkTkldOzmErnjpwyoOPLrXcWIs1w vdXHakfVHSvyb3T4gm3ZfOOoUf6lrd2w1pF/PkA88NkjN2+W9fQmbUzNgVjEQiXo 4wIDAQAB -----END PUBLIC KEY-----");
        JsonWebKey jsonWebKey = new JsonWebKey(key);
        CommonSignatureVerifier cs = new CommonSignatureVerifier(jsonWebKey);
        assertNotNull(cs);
        assertEquals("SHA256withRSA", cs.algorithm());
    }

    @Test
    public void testGetRsaPublicKeyFromConfigInvalid() {
        HashMap key = new HashMap();
        key.put(JWKParameterNames.KEY_TYPE, "RSA");
        key.put("value", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxMi4Z4");
        JsonWebKey jsonWebKey = new JsonWebKey(key);
        assertThrows(IllegalArgumentException.class, () -> new CommonSignatureVerifier(jsonWebKey));
    }
}