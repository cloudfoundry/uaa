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
package org.cloudfoundry.identity.uaa.audit.event;

import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import javax.servlet.http.HttpServletRequest;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.UaaAuditService;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;

/**
 * @author Luke Taylor
 */
public class AuditListenerTests {

    private AuditListener listener;
    private UaaAuditService auditor;
    private UaaUser user = new UaaUser("auser", "password", "auser@blah.com", "A", "User");
    private UaaAuthenticationDetails details = new UaaAuthenticationDetails(mock(HttpServletRequest.class));

    @Before
    public void setUp() throws Exception {
        auditor = mock(UaaAuditService.class);
        listener = new AuditListener(auditor);
    }

    @Test
    public void userNotFoundIsAudited() throws Exception {
        AuthzAuthenticationRequest req = new AuthzAuthenticationRequest("breakin", "password", details);
        listener.onApplicationEvent(new UserNotFoundEvent(req));
        verify(auditor).log(isA(AuditEvent.class));
    }

    @Test
    public void successfulUserAuthenticationIsAudited() throws Exception {
        listener.onApplicationEvent(new UserAuthenticationSuccessEvent(user, mock(Authentication.class)));
        verify(auditor).log(isA(AuditEvent.class));
    }

    @Test
    public void failedUserAuthenticationIsAudited() throws Exception {
        AuthzAuthenticationRequest req = new AuthzAuthenticationRequest("auser", "password", details);
        listener.onApplicationEvent(new UserAuthenticationFailureEvent(user, req));
        verify(auditor).log(isA(AuditEvent.class));
    }

}
