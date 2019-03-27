package org.cloudfoundry.identity.uaa.account.event;

import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.account.UaaPasswordTestFactory;
import org.cloudfoundry.identity.uaa.authentication.SystemAuthentication;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUserTestFactory;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.account.event.PasswordChangeEventPublisher.DEFAULT_EMAIL_DOMAIN;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PasswordChangeEventPublisherTests {

    private ScimUserProvisioning mockScimUserProvisioning;
    private ApplicationEventPublisher mockApplicationEventPublisher;
    private IdentityZoneManager mockIdentityZoneManager;
    private String currentZoneId;

    private PasswordChangeEventPublisher subject;

    private Authentication authentication;

    @BeforeEach
    void setUp() {
        mockScimUserProvisioning = mock(ScimUserProvisioning.class);
        mockApplicationEventPublisher = mock(ApplicationEventPublisher.class);
        mockIdentityZoneManager = mock(IdentityZoneManager.class);

        currentZoneId = "currentZoneId-" + RandomStringUtils.random(8);

        subject = new PasswordChangeEventPublisher(mockScimUserProvisioning, mockIdentityZoneManager);

        subject.setApplicationEventPublisher(mockApplicationEventPublisher);
        authentication = new OAuth2Authentication(
                new AuthorizationRequest(
                        "client",
                        Collections.singletonList("read")).createOAuth2Request(),
                UaaPasswordTestFactory.getAuthentication("ID", "joe", "joe@test.org")
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void passwordChange() {
        when(mockScimUserProvisioning.retrieve("foo", currentZoneId)).thenReturn(
                ScimUserTestFactory.getScimUser("joe", "joe@test.org", "Joe", "Schmo"));
        subject.passwordChange("foo");
        verify(mockApplicationEventPublisher).publishEvent(isA(PasswordChangeEvent.class));
    }

    @Test
    void passwordFailure() {
        when(mockScimUserProvisioning.retrieve("foo", currentZoneId)).thenReturn(
                ScimUserTestFactory.getScimUser("joe", "joe@test.org", "Joe", "Schmo"));
        subject.passwordFailure("foo", new RuntimeException("planned"));
        verify(mockApplicationEventPublisher).publishEvent(isA(PasswordChangeFailureEvent.class));
    }

    @Test
    void shouldReturnNullUserWhenUserIdIsUnrecognized() {
        String unknownUserId = "unknownId";
        when(mockScimUserProvisioning.retrieve(unknownUserId, currentZoneId)).thenReturn(null);
        assertNull(subject.getUser(unknownUserId));
    }

    @Test
    void shouldReturnNullWhenFindingAUserThrows() {
        String userId = "validId";
        when(mockScimUserProvisioning.retrieve(userId, currentZoneId))
                .thenThrow(new ScimResourceNotFoundException("So sad"));
        assertNull(subject.getUser(userId));
    }

    @Test
    void shouldConstructEmailBasedOnUsernameIfNoEmailList() {
        ScimUser scimUser = scimUserFrom("userName", null);
        assertEquals(String.format("userName@%s", DEFAULT_EMAIL_DOMAIN), subject.getEmail(scimUser));
    }

    @Test
    void shouldNotConstructEmailBasedOnUsernameIfNoEmailListAndTheUsernameContainsAnAtSymbol() {
        ScimUser scimUser = scimUserFrom("userName@", null);
        assertEquals("userName@", subject.getEmail(scimUser));
    }

    @Test
    void shouldConstructEmailBasedOnUsernameIfEmailListIsEmpty() {
        ScimUser scimUser = scimUserFrom("userName", Collections.emptyList());
        assertEquals(String.format("userName@%s", DEFAULT_EMAIL_DOMAIN), subject.getEmail(scimUser));
    }

    @Test
    void shouldConstructEmailBasedOnUsernameIfEmailListIsEmptyAndTheUsernameContainsAnAtSymbol() {
        ScimUser scimUser = scimUserFrom("userName@", Collections.emptyList());
        assertEquals("userName@", subject.getEmail(scimUser));
    }

    @Test
    void shouldReturnFirstEmailFromEmailListIfNoPrimary() {
        ScimUser scimUser = scimUserFrom("userName", Arrays.asList("a@example.com", "b@example.com"));
        assertEquals("a@example.com", subject.getEmail(scimUser));
    }

    @Test
    void shouldReturnFirstPrimaryEmail() {
        ScimUser scimUser = scimUserFrom("userName", Arrays.asList("a@example.com", "b@example.com", "c@example.com"));
        scimUser.getEmails().get(1).setPrimary(true);
        assertEquals("b@example.com", subject.getEmail(scimUser));
    }

    @Test
    void notAuthenticatedReturnsSystemAuth() {
        assertSame(authentication, subject.getPrincipal());
        SecurityContextHolder.clearContext();
        assertSame(SystemAuthentication.SYSTEM_AUTHENTICATION, subject.getPrincipal());
    }

    private ScimUser scimUserFrom(String userName, List<String> emailAddresses) {
        ScimUser scimUser = new ScimUser(userName, userName, userName, userName);
        if (emailAddresses != null) {
            List<ScimUser.Email> emails = emailAddresses.stream().map((emailAddress) -> {
                ScimUser.Email email = new ScimUser.Email();
                email.setValue(emailAddress);
                return email;
            }).collect(Collectors.toList());

            scimUser.setEmails(emails);
        }
        return scimUser;
    }
}
