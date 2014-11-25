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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpoints;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class UaaChangePasswordServiceTest {
    private UaaChangePasswordService subject;
    private PasswordResetEndpoints passwordResetEndpoints;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        passwordResetEndpoints = mock(PasswordResetEndpoints.class);
        subject = new UaaChangePasswordService(passwordResetEndpoints);
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testChangePassword() throws Exception {
        Map<String,String> userInfo = new HashMap<>();
        userInfo.put("user_id", "the user id");
        userInfo.put("username", "the user name");
        when(passwordResetEndpoints.changePassword(any(PasswordResetEndpoints.PasswordChange.class))).thenReturn(new ResponseEntity<>(userInfo, HttpStatus.OK));
        subject.changePassword("the user name", "current password", "new password");
        verify(passwordResetEndpoints).changePassword(any(PasswordResetEndpoints.PasswordChange.class));
    }
}