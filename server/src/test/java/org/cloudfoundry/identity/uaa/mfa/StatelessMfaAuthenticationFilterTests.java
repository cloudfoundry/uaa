/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mfa;

import javax.servlet.FilterChain;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import com.google.common.collect.Lists;
import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.JdbcAuditService;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.CommonLoginPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.LockoutPolicyRetriever;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mfa.exception.InvalidMfaCodeException;
import org.cloudfoundry.identity.uaa.mfa.exception.MissingMfaCodeException;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigDoesNotExistException;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;

import com.jayway.jsonassert.JsonAssert;
import org.joda.time.DateTimeUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import static org.cloudfoundry.identity.uaa.mfa.MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;

public class StatelessMfaAuthenticationFilterTests {

    public static final String MFA_CODE = "mfaCode";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private UserGoogleMfaCredentialsProvisioning googleAuthenticator;
    private Set<String> grantTypes;
    private StatelessMfaAuthenticationFilter filter;
    private FilterChain chain;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private OAuth2Authentication authentication;
    private OAuth2Request storedOAuth2Request;
    private UaaAuthentication uaaAuthentication;
    private MfaProviderProvisioning mfaProvider;
    private IdentityZone zone;
    private UaaUserDatabase userDatabase;
    private UaaUser user;
    private ApplicationEventPublisher publisher;
    private JdbcAuditService jdbcAuditServiceMock;
    private LockoutPolicyRetriever lockoutPolicyRetriever;
    private TimeService timeService;
    private CommonLoginPolicy commonLoginPolicy;

    @After
    public void teardown() {
        IdentityZoneHolder.clear();
    }

    @Before
    public void setup() {
        zone = MultitenancyFixture.identityZone("id", "id");
        zone.getConfig().getMfaConfig().setEnabled(true).setProviderName("mfa-provider-name");
        IdentityZoneHolder.set(zone);

        storedOAuth2Request = mock(OAuth2Request.class);
        UaaPrincipal uaaPrincipal = new UaaPrincipal("1", "marissa", "marissa@test.org", OriginKeys.UAA, null, zone.getId());
        uaaAuthentication = new UaaAuthentication(uaaPrincipal, Collections.emptyList(), mock(UaaAuthenticationDetails.class));
        uaaAuthentication.setAuthenticationMethods(new HashSet<>(Collections.singletonList("pwd")));
        authentication = new OAuth2Authentication(storedOAuth2Request, uaaAuthentication);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        googleAuthenticator = mock(UserGoogleMfaCredentialsProvisioning.class);
        when(googleAuthenticator.activeUserCredentialExists(anyString(), anyString())).thenReturn(true);
        when(googleAuthenticator.isValidCode(any(), eq(123456))).thenReturn(true);
        when(googleAuthenticator.isValidCode(any(), not(eq(123456)))).thenReturn(false);
        when(googleAuthenticator.getUserGoogleMfaCredentials(anyString(), anyString())).thenReturn(mock(UserGoogleMfaCredentials.class));
        grantTypes = new HashSet<>(Collections.singletonList("password"));

        mfaProvider = mock(MfaProviderProvisioning.class);
        when(mfaProvider.retrieveByName(anyString(), anyString())).thenReturn(
          new MfaProvider().setName("mfa-provider-name").setId("mfa-provider-id").setType(GOOGLE_AUTHENTICATOR)
        );

        userDatabase = mock(UaaUserDatabase.class);
        user = new UaaUser(
          new UaaUserPrototype()
            .withUsername(uaaPrincipal.getName())
            .withEmail(uaaPrincipal.getEmail())
            .withId(uaaPrincipal.getId())
        );
        when(userDatabase.retrieveUserById(anyString())).thenReturn(user);

        publisher = mock(ApplicationEventPublisher.class);
        jdbcAuditServiceMock = mock(JdbcAuditService.class);

        lockoutPolicyRetriever = mock(LockoutPolicyRetriever.class);
        LockoutPolicy lockoutPolicy = new LockoutPolicy(0, 5, 60);
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(lockoutPolicy);

        timeService = mock(TimeService.class);
        when(timeService.getCurrentTimeMillis()).thenReturn(1l);

        boolean mfaLockoutPolicyEnabled = true;
        commonLoginPolicy = new CommonLoginPolicy(jdbcAuditServiceMock, lockoutPolicyRetriever, AuditEventType.MfaAuthenticationSuccess, AuditEventType.MfaAuthenticationFailure, timeService, mfaLockoutPolicyEnabled);

        filter = new StatelessMfaAuthenticationFilter(googleAuthenticator, grantTypes, mfaProvider, userDatabase, commonLoginPolicy);
        filter.setApplicationEventPublisher(publisher);

        chain = mock(FilterChain.class);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();

        request.setParameter(GRANT_TYPE, "password");
        request.setParameter("client_id", "clientID");
        request.setParameter("client_secret", "secret");
        request.setParameter("username", "marissa");
        request.setParameter("password", "koala");
        request.setParameter(MFA_CODE, "123456");
    }

    @Test
    public void only_password_grant_type() {
        assertTrue(filter.isGrantTypeSupported("password"));
        assertFalse(filter.isGrantTypeSupported("other"));
    }

    @Test
    public void non_password_grants_ignored() throws Exception {
        request.setParameter(GRANT_TYPE, "other-than-password");
        filter.doFilterInternal(request, response, chain);
        verifyNoInteractions(googleAuthenticator);
        verify(chain).doFilter(same(request), same(response));
        verifyNoInteractions(publisher);
    }

    @Test
    public void authentication_missing() throws Exception {
        exception.expect(InsufficientAuthenticationException.class);
        exception.expectMessage("User authentication missing");
        SecurityContextHolder.clearContext();
        checkMfaCodeNoMfaInteraction();
    }

    private void checkMfaCodeNoMfaInteraction() {
        try {
            filter.checkMfaCode(request);
        } catch (Exception e) {
            verifyNoInteractions(chain);
            verifyNoInteractions(googleAuthenticator);
            throw e;
        }
    }

    @Test
    public void authentication_wrong_type() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(mock(UaaAuthentication.class));
        exception.expect(InsufficientAuthenticationException.class);
        exception.expectMessage("Unrecognizable authentication");
        checkMfaCodeNoMfaInteraction();

    }

    @Test
    public void user_authentication_wrong_type() throws Exception {
        authentication = new OAuth2Authentication(storedOAuth2Request, mock(Authentication.class));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        exception.expect(InsufficientAuthenticationException.class);
        exception.expectMessage("Unrecognizable user authentication");
        checkMfaCodeNoMfaInteraction();
    }

    @Test
    public void mfa_validation_works() throws Exception {
        filter.doFilterInternal(request, response, chain);
        verify(googleAuthenticator).isValidCode(any(), eq(123456));
        verify(chain).doFilter(same(request), same(response));
        assertThat(uaaAuthentication.getAuthenticationMethods(), containsInAnyOrder("pwd", "otp", "mfa"));
        verify(publisher, times(1)).publishEvent(any(MfaAuthenticationSuccessEvent.class));
        verify(publisher, times(1)).publishEvent(any(ApplicationEvent.class));

    }

    @Test
    public void mfa_code_missing() throws Exception {
        request.removeParameter(MFA_CODE);
        exception.expect(MissingMfaCodeException.class);
        exception.expectMessage("A multi-factor authentication code is required to complete the request");
        checkMfaCodeNoMfaInteraction();
    }

    @Test
    public void mfa_code_missing_returns_json_error() throws Exception {
        request.removeParameter(MFA_CODE);
        filter.doFilterInternal(request, response, chain);
        assertThat(response.getStatus(), equalTo(400));
        JsonAssert.with(response.getContentAsString())
          .assertThat("error", equalTo("invalid_request"))
          .assertThat("error_description", equalTo("A multi-factor authentication code is required to complete the request"));
        verify(publisher, times(1)).publishEvent(any(MfaAuthenticationFailureEvent.class));
        verify(publisher, times(1)).publishEvent(any(ApplicationEvent.class));
    }

    @Test
    public void invalid_mfa_code() {
        request.setParameter(MFA_CODE, "54321");
        exception.expect(InvalidMfaCodeException.class);
        checkMfaCode();
    }

    @Test
    public void invalid_mfa_code_returns_json_bad_credentials() throws Exception {
        request.setParameter(MFA_CODE, "54321");
        filter.doFilterInternal(request, response, chain);
        assertThat(response.getStatus(), equalTo(401));
        JsonAssert.with(response.getContentAsString())
          .assertThat("error", equalTo("unauthorized"))
          .assertThat("error_description", equalTo("Bad credentials"));
        verify(publisher, times(1)).publishEvent(any(MfaAuthenticationFailureEvent.class));
        verify(publisher, times(1)).publishEvent(any(ApplicationEvent.class));
    }

    private void checkMfaCode() {
        try {
            filter.checkMfaCode(request);
        } catch (Exception x) {
            verifyNoInteractions(chain);
            throw x;
        }
    }

    @Test
    public void user_config_is_missing() {
        when(googleAuthenticator.getUserGoogleMfaCredentials(anyString(), anyString())).thenReturn(null);
        exception.expect(UserMfaConfigDoesNotExistException.class);
        exception.expectMessage("User must register a multi-factor authentication token");
        checkMfaCode();
    }

    @Test
    public void user_config_is_returning_error() throws Exception {
        when(googleAuthenticator.getUserGoogleMfaCredentials(anyString(), anyString())).thenReturn(null);
        filter.doFilterInternal(request, response, chain);
        assertThat(response.getStatus(), equalTo(400));
        assertThat(response.getHeader(HttpHeaders.CONTENT_TYPE), equalTo(MediaType.APPLICATION_JSON_VALUE));
        assertNotNull(response.getContentAsString());
        JsonAssert.with(response.getContentAsString())
          .assertThat("error", equalTo("invalid_request"))
          .assertThat("error_description", equalTo("User must register a multi-factor authentication token"));
        verify(publisher, times(1)).publishEvent(any(MfaAuthenticationFailureEvent.class));
        verify(publisher, times(1)).publishEvent(any(ApplicationEvent.class));
    }

    @Test
    public void no_mfa_configured() throws Exception {
        zone.getConfig().getMfaConfig().setEnabled(false);
        filter.doFilterInternal(request, response, chain);
        verifyNoInteractions(googleAuthenticator);
        verifyNoInteractions(mfaProvider);
        verify(chain).doFilter(same(request), same(response));
        verifyNoInteractions(publisher);
    }


    @After
    public void unfreezeTime() {
        DateTimeUtils.setCurrentMillisSystem();
    }

    @Test
    public void when_valid_mfa_auth_code_given_but_mfa_is_locked_out_should_fail() {
        long fixedTime = 1L;
        when(timeService.getCurrentTimeMillis()).thenReturn(fixedTime);

        MfaAuthenticationFailureEvent event = new MfaAuthenticationFailureEvent(user, authentication, GOOGLE_AUTHENTICATOR.toValue(), IdentityZoneHolder.getCurrentZoneId());
        when(jdbcAuditServiceMock.find(user.getId(), fixedTime, zone.getId())).thenReturn(Lists.newArrayList(event.getAuditEvent()));

        LockoutPolicy lockoutPolicy = new LockoutPolicy(0, 1, 5);
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(lockoutPolicy);

        request.setParameter(MFA_CODE, "123456");

        exception.expect(RuntimeException.class);
        filter.checkMfaCode(request);
    }

    @Test
    public void when_valid_mfa_auth_code_given_but_mfa_policy_is_disabled_should_not_fail() {
        boolean mfaPolicyEnabled = false;
        commonLoginPolicy = new CommonLoginPolicy(jdbcAuditServiceMock, lockoutPolicyRetriever, AuditEventType.MfaAuthenticationSuccess, AuditEventType.MfaAuthenticationFailure, timeService, mfaPolicyEnabled);
        filter = new StatelessMfaAuthenticationFilter(googleAuthenticator, grantTypes, mfaProvider, userDatabase, commonLoginPolicy);
        filter.setApplicationEventPublisher(publisher);

        long fixedTime = 1L;
        when(timeService.getCurrentTimeMillis()).thenReturn(fixedTime);

        MfaAuthenticationFailureEvent event = new MfaAuthenticationFailureEvent(user, authentication, GOOGLE_AUTHENTICATOR.toValue(), IdentityZoneHolder.getCurrentZoneId());
        when(jdbcAuditServiceMock.find(user.getId(), fixedTime, zone.getId())).thenReturn(Lists.newArrayList(event.getAuditEvent()));

        LockoutPolicy lockoutPolicy = new LockoutPolicy(0, 1, 5);
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(lockoutPolicy);

        request.setParameter(MFA_CODE, "123456");

        filter.checkMfaCode(request);
    }

    @Test
    public void when_valid_mfa_auth_code_given_with_previously_failed_mfa_auth_attempts_but_not_locked_out_should_pass() {
        long fixedTime = 1L;
        when(timeService.getCurrentTimeMillis()).thenReturn(fixedTime);

        MfaAuthenticationFailureEvent event = new MfaAuthenticationFailureEvent(user, authentication, GOOGLE_AUTHENTICATOR.toValue(), IdentityZoneHolder.getCurrentZoneId());
        when(jdbcAuditServiceMock.find(user.getId(), fixedTime, zone.getId())).thenReturn(Lists.newArrayList(event.getAuditEvent()));

        LockoutPolicy lockoutPolicy = new LockoutPolicy(1, 2, 5);
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(lockoutPolicy);

        request.setParameter(MFA_CODE, "123456");

        filter.checkMfaCode(request);
    }

    @Test
    public void when_valid_mfa_auth_code_given_with_previously_failed_mfa_auth_attempts_interleaved_with_successful_mfa_auth_event_but_not_locked_out_should_pass() {
        long fixedTime = 1L;
        when(timeService.getCurrentTimeMillis()).thenReturn(fixedTime);


        AuditEvent failedMfaEvent = new MfaAuthenticationFailureEvent(user, authentication, GOOGLE_AUTHENTICATOR.toValue(), IdentityZoneHolder.getCurrentZoneId()).getAuditEvent();
        AuditEvent successfulMfaEvent = new MfaAuthenticationSuccessEvent(user, authentication, GOOGLE_AUTHENTICATOR.toValue(), IdentityZoneHolder.getCurrentZoneId()).getAuditEvent();
        ArrayList<AuditEvent> events = Lists.newArrayList(failedMfaEvent, failedMfaEvent, successfulMfaEvent, failedMfaEvent);
        when(jdbcAuditServiceMock.find(user.getId(), fixedTime, zone.getId())).thenReturn(events);

        LockoutPolicy lockoutPolicy = new LockoutPolicy(1, 3, 5);
        when(lockoutPolicyRetriever.getLockoutPolicy()).thenReturn(lockoutPolicy);

        request.setParameter(MFA_CODE, "123456");

        filter.checkMfaCode(request);
    }

}