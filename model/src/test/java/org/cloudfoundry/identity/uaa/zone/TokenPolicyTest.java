package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

import static org.junit.Assert.*;

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

public class TokenPolicyTest {

    @Test
    public void deserializationOfTokenPolicyWithVerificationKey_doesNotFail() {
        String jsonTokenPolicy = "{\"keys\":{\"key-id-1\":{\"verificationKey\":\"some-verification-key-1\",\"signingKey\":\"some-signing-key-1\"}}}";
        TokenPolicy tokenPolicy = JsonUtils.readValue(jsonTokenPolicy, TokenPolicy.class);
        assertEquals(tokenPolicy.getKeys().get("key-id-1").getSigningKey(), "some-signing-key-1");
    }

}