/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
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

package org.cloudfoundry.identity.uaa.authentication.event;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.Authentication;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.Mockito.mock;

public class UserAuthenticationSuccessEventTests {

    @Test
    public void get_origin_from_request() throws Exception {
        MockHttpSession session = new MockHttpSession(null, "the-id");
        MockHttpServletRequest request = new MockHttpServletRequest("GET","/oauth/authorize");
        request.setSession(session);
        request.setRemoteAddr("127.10.10.10");
        UaaAuthenticationDetails details = new UaaAuthenticationDetails(request, "client-id");

        UserAuthenticationSuccessEvent event = new UserAuthenticationSuccessEvent(mock(UaaUser.class), mock(Authentication.class));
        String origin = event.getOrigin(details);

        assertThat(origin, containsString("remoteAddress=127.10.10.10"));
        assertThat(origin, containsString("clientId=client-id"));
        assertThat(origin, containsString("sessionId=<SESSION>"));
    }
}