/*
 * *****************************************************************************
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;
import java.util.List;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class UaaChangePasswordServiceTest {
    private UaaChangePasswordService subject;
    private ScimUserProvisioning scimUserProvisioning;
    private PasswordValidator passwordValidator;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        SecurityContextHolder.getContext().setAuthentication(new MockAuthentication());
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        passwordValidator = mock(PasswordValidator.class);
        subject = new UaaChangePasswordService(scimUserProvisioning, passwordValidator);
    }

    @Test
    void changePasswordWithNoCurrentPasswordOrUsername() {
        assertThatExceptionOfType(BadCredentialsException.class).isThrownBy(() ->
                subject.changePassword(null, null, "newPassword"));
    }

    @Test
    void changePasswordWithInvalidNewPassword() {
        doThrow(new InvalidPasswordException("")).when(passwordValidator).validate("invPawd");
        assertThatExceptionOfType(InvalidPasswordException.class).isThrownBy(() ->
                subject.changePassword("username", "currentPassword", "invPawd"));
    }

    @Test
    void changePasswordWithUserNotFound() {
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(emptyList());
        assertThatExceptionOfType(ScimResourceNotFoundException.class).isThrownBy(() ->
                subject.changePassword("username", "currentPassword", "validPassword"));
        verify(passwordValidator).validate("validPassword");
        verify(scimUserProvisioning).retrieveByUsernameAndOriginAndZone(anyString(), eq(OriginKeys.UAA), eq(zoneId));
    }

    @Test
    void changePassword_ReturnsUnprocessableEntity_PasswordNoveltyViolation() {
        List<ScimUser> results = getScimUsers();
        when(scimUserProvisioning.retrieveByUsernameAndOriginAndZone(
                anyString(),
                eq(OriginKeys.UAA),
                eq(IdentityZoneHolder.get().getId()))
        ).thenReturn(results);

        when(scimUserProvisioning.checkPasswordMatches("id", "samePassword1", IdentityZoneHolder.get().getId())).thenReturn(true);
        assertThatThrownBy(() -> subject.changePassword("username", "samePassword1", "samePassword1"))
                .isInstanceOf(InvalidPasswordException.class)
                .hasMessage("Your new password cannot be the same as the old password.");
    }

    @Test
    void changePassword() {
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
