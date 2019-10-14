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
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.List;

import static java.util.Collections.emptyList;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class UaaChangePasswordServiceTest {
    private UaaChangePasswordService subject;
    private ScimUserProvisioning scimUserProvisioning;
    private PasswordValidator passwordValidator;

    @Before
    public void setUp() {
        SecurityContextHolder.clearContext();
        SecurityContextHolder.getContext().setAuthentication(new MockAuthentication());
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        passwordValidator = mock(PasswordValidator.class);
        subject = new UaaChangePasswordService(scimUserProvisioning, passwordValidator);
    }

    @Test(expected = BadCredentialsException.class)
    public void testChangePasswordWithNoCurrentPasswordOrUsername() {
        subject.changePassword(null, null, "newPassword");
    }

    @Test(expected = InvalidPasswordException.class)
    public void testChangePasswordWithInvalidNewPassword() {
        doThrow(new InvalidPasswordException("")).when(passwordValidator).validate("invPawd");
        subject.changePassword("username", "currentPassword", "invPawd");
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void testChangePasswordWithUserNotFound() {
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(emptyList());
        subject.changePassword("username", "currentPassword", "validPassword");
        verify(passwordValidator).validate("validPassword");
        verify(scimUserProvisioning).query(anyString(), zoneId);
    }

    @Test
    public void changePassword_ReturnsUnprocessableEntity_PasswordNoveltyViolation() {
        List<ScimUser> results = getScimUsers();
        when(scimUserProvisioning.retrieveByUsernameAndOriginAndZone(
                anyString(),
                eq(OriginKeys.UAA),
                eq(IdentityZoneHolder.get().getId()))
        ).thenReturn(results);

        when(scimUserProvisioning.checkPasswordMatches("id", "samePassword1", IdentityZoneHolder.get().getId())).thenReturn(true);
        try {
            subject.changePassword("username", "samePassword1", "samePassword1");
            fail();
        } catch (InvalidPasswordException e) {
            assertEquals("Your new password cannot be the same as the old password.", e.getLocalizedMessage());
        }
    }

    @Test
    public void testChangePassword() {
        List<ScimUser> results = getScimUsers();
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.retrieveByUsernameAndOriginAndZone(anyString(), eq(OriginKeys.UAA), eq(zoneId))).thenReturn(results);
        subject.changePassword("username", "currentPassword", "validPassword");
        verify(passwordValidator).validate("validPassword");
        verify(scimUserProvisioning).retrieveByUsernameAndOriginAndZone(anyString(), eq(OriginKeys.UAA), eq(zoneId));
        verify(scimUserProvisioning).changePassword("id", "currentPassword", "validPassword", zoneId);
    }

    @Test
    public void testQueryContainsOriginUaa() {
        List<ScimUser> results = getScimUsers();
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.retrieveByUsernameAndOriginAndZone(anyString(), eq(OriginKeys.UAA), eq(zoneId))).thenReturn(results);
        subject.changePassword("username", "currentPassword", "validPassword");
        verify(passwordValidator).validate("validPassword");
        verify(scimUserProvisioning).retrieveByUsernameAndOriginAndZone(anyString(), eq(OriginKeys.UAA), eq(zoneId));
        verify(scimUserProvisioning).changePassword("id", "currentPassword", "validPassword", zoneId);
    }

    private List<ScimUser> getScimUsers() {
        ScimUser.Email email = new ScimUser.Email();
        email.setValue("username@test.com");
        ScimUser user = new ScimUser("id", "username", "givenName", "familyName");
        user.setEmails(Collections.singletonList(email));
        return Collections.singletonList(user);
    }
}
