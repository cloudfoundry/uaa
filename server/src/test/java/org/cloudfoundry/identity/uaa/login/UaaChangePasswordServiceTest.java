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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.UaaChangePasswordService;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class UaaChangePasswordServiceTest {
    private UaaChangePasswordService subject;
    private ScimUserProvisioning scimUserProvisioning;
    private PasswordValidator passwordValidator;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        SecurityContextHolder.getContext().setAuthentication(new MockAuthentication());
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        passwordValidator = mock(PasswordValidator.class);
        subject = new UaaChangePasswordService(scimUserProvisioning, passwordValidator);
    }

    @Test(expected = BadCredentialsException.class)
    public void testChangePasswordWithNoCurrentPasswordOrUsername() throws Exception {
        subject.changePassword(null, null, "newPassword");
    }

    @Test(expected = InvalidPasswordException.class)
    public void testChangePasswordWithInvalidNewPassword() throws Exception {
        doThrow(new InvalidPasswordException("")).when(passwordValidator).validate("invPawd");
        subject.changePassword("username", "currentPassword", "invPawd");
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void testChangePasswordWithUserNotFound() {
        List<ScimUser> results = Collections.emptyList();
        when(scimUserProvisioning.query(anyString())).thenReturn(results);
        subject.changePassword("username", "currentPassword", "validPassword");
        verify(passwordValidator).validate("validPassword");
        verify(scimUserProvisioning).query(anyString());
    }

    @Test
    public void changePassword_ReturnsUnprocessableEntity_PasswordNoveltyViolation() {
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("username@test.com");
        ScimUser user = new ScimUser("id", "username", "givenName", "familyName");
        user.setEmails(Collections.singletonList(email));
        List<ScimUser> results = Collections.singletonList(user);
        when(scimUserProvisioning.query(anyString())).thenReturn(results);
        when(scimUserProvisioning.checkPasswordMatches("id", "samePassword1")).thenReturn(true);
        try {
            subject.changePassword("username", "samePassword1", "samePassword1");
            fail();
        } catch (InvalidPasswordException e) {
            assertEquals("Your new password cannot be the same as the old password.", e.getLocalizedMessage());
        }
    }

    @Test
    public void testChangePassword() {
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("username@test.com");
        ScimUser user = new ScimUser("id", "username", "givenName", "familyName");
        user.setEmails(Collections.singletonList(email));
        List<ScimUser> results = Collections.singletonList(user);
        when(scimUserProvisioning.query(anyString())).thenReturn(results);
        subject.changePassword("username", "currentPassword", "validPassword");
        verify(passwordValidator).validate("validPassword");
        verify(scimUserProvisioning).query(anyString());
        verify(scimUserProvisioning).changePassword("id", "currentPassword", "validPassword");
    }
}
