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

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.password.event.ResetPasswordRequestEvent;
import org.cloudfoundry.identity.uaa.scim.ScimMeta;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.sameInstance;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.contains;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class UaaResetPasswordServiceTests {

    private UaaResetPasswordService emailResetPasswordService;
    private ExpiringCodeStore codeStore;
    private ScimUserProvisioning scimUserProvisioning;
    private PasswordValidator passwordValidator;

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        codeStore = mock(ExpiringCodeStore.class);
        passwordValidator = mock(PasswordValidator.class);
        emailResetPasswordService = new UaaResetPasswordService(scimUserProvisioning, codeStore, passwordValidator);
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void forgotPassword_ResetCodeIsReturnedSuccessfully() throws Exception {
        ScimUser user = new ScimUser("user-id-001","user@example.com","firstName","lastName");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.query(contains("origin"))).thenReturn(Arrays.asList(user));
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis());
        when(codeStore.generateCode(anyString(), any(Timestamp.class))).thenReturn(new ExpiringCode("code", expiresAt, "user-id-001"));

        ForgotPasswordInfo forgotPasswordInfo = emailResetPasswordService.forgotPassword("user@example.com");
        assertThat(forgotPasswordInfo.getUserId(), equalTo("user-id-001"));

        ExpiringCode resetPasswordCode = forgotPasswordInfo.getResetPasswordCode();
        assertThat(resetPasswordCode.getCode(), equalTo("code"));
        assertThat(resetPasswordCode.getExpiresAt(), equalTo(expiresAt));
        assertThat(resetPasswordCode.getData(), equalTo("user-id-001"));
    }

    @Test
    public void forgotPassword_PublishesResetPasswordRequestEvent() throws Exception {
        ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
        Authentication authentication = mock(Authentication.class);
        emailResetPasswordService.setApplicationEventPublisher(publisher);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        ScimUser user = new ScimUser("user-id-001", "user@example.com", "firstName", "lastName");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.query(contains("origin"))).thenReturn(Arrays.asList(user));
        Timestamp expiresAt = new Timestamp(System.currentTimeMillis());
        when(codeStore.generateCode(anyString(), any(Timestamp.class))).thenReturn(new ExpiringCode("code", expiresAt, "user-id-001"));

        emailResetPasswordService.forgotPassword("user@example.com");
        ArgumentCaptor<ResetPasswordRequestEvent> captor = ArgumentCaptor.forClass(ResetPasswordRequestEvent.class);
        verify(publisher).publishEvent(captor.capture());
        ResetPasswordRequestEvent event = captor.getValue();
        assertThat((String) event.getSource(), equalTo("user@example.com"));
        assertThat(event.getCode(), equalTo("code"));
        assertThat(event.getAuthentication(), sameInstance(authentication));
    }

    @Test
    public void forgotPassword_ThrowsConflictException() throws Exception {
        ScimUser user = new ScimUser("user-id-001","user@example.com","firstName","lastName");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.query(contains("origin"))).thenReturn(Arrays.asList(new ScimUser[]{}));
        when(scimUserProvisioning.query(eq("userName eq \"user@example.com\""))).thenReturn(Arrays.asList(new ScimUser[]{user}));
        when(codeStore.generateCode(anyString(), any(Timestamp.class))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), "user-id-001"));
        when(codeStore.retrieveCode(anyString())).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()),"user-id-001"));

        try {
            emailResetPasswordService.forgotPassword("user@example.com");
            fail();
        } catch (ConflictException e) {
            assertThat(e.getUserId(), equalTo("user-id-001"));
        }
    }

    @Test(expected = NotFoundException.class)
    public void forgotPassword_ThrowsNotFoundException_ScimUserNotFoundInUaa() throws Exception {
        emailResetPasswordService.forgotPassword("user@example.com");
    }

    @Test
    public void testResetPassword() throws Exception {
        ScimUser user = new ScimUser("usermans-id","userman","firstName","lastName");
        user.setMeta(new ScimMeta(new Date(System.currentTimeMillis()-(1000*60*60*24)), new Date(System.currentTimeMillis()-(1000*60*60*24)), 0));
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.retrieve(eq("usermans-id"))).thenReturn(user);
        when(codeStore.retrieveCode(eq("secret_code"))).thenReturn(new ExpiringCode("code", new Timestamp(System.currentTimeMillis()), "usermans-id"));
        SecurityContext securityContext = mock(SecurityContext.class);
        when(securityContext.getAuthentication()).thenReturn(new Authentication() {
            @Override
            public Collection<? extends GrantedAuthority> getAuthorities() {
                return null;
            }

            @Override
            public Object getCredentials() {
                return null;
            }

            @Override
            public Object getDetails() {
                return null;
            }

            @Override
            public Object getPrincipal() {
                return null;
            }

            @Override
            public boolean isAuthenticated() {
                return false;
            }

            @Override
            public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {

            }

            @Override
            public String getName() {
                return null;
            }
        });
        SecurityContextHolder.setContext(securityContext);

        user = emailResetPasswordService.resetPassword("secret_code", "new_secret");

        Assert.assertEquals("usermans-id", user.getId());
        Assert.assertEquals("userman", user.getUserName());
    }

    @Test(expected = UaaException.class)
    public void testResetPasswordWhenTheCodeIsDenied() throws Exception {
        emailResetPasswordService.resetPassword("b4d_k0d3z", "new_password");
    }

    @Test(expected = InvalidPasswordException.class)
    public void resetPassword_validatesNewPassword() {
        when(passwordValidator.validate("new_secret")).thenThrow(new InvalidPasswordException("foo"));
        emailResetPasswordService.resetPassword("secret_code", "new_secret");
    }
}
