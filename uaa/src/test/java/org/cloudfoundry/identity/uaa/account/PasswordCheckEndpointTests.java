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

package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.account.PasswordCheckEndpoint;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordScore;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;

import static junit.framework.Assert.assertEquals;

/**
 * @author Luke Taylor
 */
public class PasswordCheckEndpointTests {

    @Test
    public void checkReturnsExpectedScore() throws Exception {
        PasswordCheckEndpoint pc = new PasswordCheckEndpoint();
        MockHttpServletResponse response = new MockHttpServletResponse();
        PasswordScore score = pc.passwordScore("password1", "", response);

        assertEquals(0, score.getScore());
        assertEquals(0, score.getRequiredScore());
        assertEquals("Endpoint+deprecated", response.getHeader("X-Cf-Warnings"));
    }
}
