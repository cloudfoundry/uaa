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

import static org.junit.Assert.assertEquals;

import org.cloudfoundry.identity.uaa.oauth.SignerProvider;
import org.cloudfoundry.identity.uaa.oauth.TokenKeyEndpoint;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Map;

/**
 * @author Dave Syer
 * @author Luke Taylor
 * @author Joel D'sa
 */
public class TokenKeyEndpointTests {

    private TokenKeyEndpoint tokenEnhancer = new TokenKeyEndpoint();
    private SignerProvider signerProvider = new SignerProvider();

    @Before
    public void setUp() throws Exception {
        tokenEnhancer.setSignerProvider(signerProvider);
    }

    @Test
    public void sharedSecretIsReturnedFromTokenKeyEndpoint() throws Exception {
        signerProvider.setVerifierKey("someKey");
        VerificationKeyResponse response = tokenEnhancer.getKey(new UsernamePasswordAuthenticationToken("foo", "bar"));
        assertEquals("HMACSHA256", response.getAlgorithm());
        assertEquals("someKey", response.getKey());
        assertEquals("MAC", response.getType());
        assertEquals("sig", response.getUse());
    }

    @Test(expected = AccessDeniedException.class)
    public void sharedSecretCannotBeAnonymouslyRetrievedFromTokenKeyEndpoint() throws Exception {
        signerProvider.setVerifierKey("someKey");
        assertEquals("{alg=HMACSHA256, value=someKey}",
            tokenEnhancer.getKey(
                new AnonymousAuthenticationToken("anon", "anonymousUser", AuthorityUtils
                    .createAuthorityList("ROLE_ANONYMOUS"))).toString());
    }

    @Test
    public void responseIsBackwardCompatibleWithMap() {
        signerProvider.setVerifierKey("someKey");
        VerificationKeyResponse response = tokenEnhancer.getKey(new UsernamePasswordAuthenticationToken("foo", "bar"));

        String serialized = JsonUtils.writeValueAsString(response);

        Map<String, String> deserializedMap = JsonUtils.readValue(serialized, Map.class);
        assertEquals("HMACSHA256", deserializedMap.get("alg"));
        assertEquals("someKey", deserializedMap.get("value"));
        assertEquals("MAC", deserializedMap.get("kty"));
        assertEquals("sig", deserializedMap.get("use"));
    }
}
