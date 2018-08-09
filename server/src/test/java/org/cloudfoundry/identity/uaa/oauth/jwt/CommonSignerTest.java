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

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class CommonSignerTest {
    private String rsaSigningKey;
    private String macSigningKey;

    @Before
    public void setup() {
        rsaSigningKey = "-----BEGIN RSA PRIVATE KEY-----\n" +
            "MIIBOQIBAAJAcjAgsHEfrUxeTFwQPb17AkZ2Im4SfZdpY8Ada9pZfxXz1PZSqv9T\n" +
            "PTMAzNx+EkzMk2IMYN+uNm1bfDzaxVdz+QIDAQABAkBoR39y4rw0/QsY3PKQD5xo\n" +
            "hYSZCMCmJUI/sFCuECevIFY4h6q9KBP+4Set96f7Bgs9wJWVvCMx/nJ6guHAjsIB\n" +
            "AiEAywVOoCGIZ2YzARXWYcMRYZ89hxoHh8kZ+QMthRSZieECIQCP/GWQYgyofAQA\n" +
            "BtM8YwThXEV+S3KtuCn4IAQ89gqdGQIgULBASpZpPyc4OEM0nFBKFTGT46EtwwLj\n" +
            "RrvDmLPSPiECICQi9FqIQSUH+vkGvX0qXM8ymT5ZMS7oSaA8aNPj7EYBAiEAx5V3\n" +
            "2JGEulMY3bK1PVGYmtsXF1gq6zbRMoollMCRSMg=\n" +
            "-----END RSA PRIVATE KEY-----";
        macSigningKey = "mac-sign-key";
    }

    @Test
    public void test_rsa_key_null_id() {
        CommonSigner signer = new CommonSigner(null, rsaSigningKey, "http://localhost/uaa");
        assertEquals("RS256", signer.algorithm());
        assertNull(signer.keyId());
    }

    @Test
    public void test_rsa_key_with_id() {
        CommonSigner signer = new CommonSigner("id", rsaSigningKey, "http://localhost/uaa");
        assertEquals("RS256", signer.algorithm());
        assertEquals("id", signer.keyId());
    }

    @Test
    public void test_mac_key_null_id() {
        CommonSigner signer = new CommonSigner(null, macSigningKey, "http://localhost/uaa");
        assertEquals("HS256", signer.algorithm());
        assertNull(signer.keyId());
    }

    @Test
    public void test_mac_key_with_id() {
        CommonSigner signer = new CommonSigner("id", macSigningKey, "http://localhost/uaa");
        assertEquals("HS256", signer.algorithm());
        assertEquals("id", signer.keyId());
    }

    @Test(expected = IllegalArgumentException.class)
    public void null_key_is_rejected() {
        new CommonSigner("id", null, "http://localhost/uaa");
    }

}