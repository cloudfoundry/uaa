package org.cloudfoundry.identity.uaa.account.event;

import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.account.UaaPasswordTestFactory;
import org.cloudfoundry.identity.uaa.authentication.SystemAuthentication;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.account.event.PasswordChangeEventPublisher.DEFAULT_EMAIL_DOMAIN;
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
        assertThat(subject.getUser(unknownUserId)).isNull();
    }

    @Test
    void shouldReturnNullWhenFindingAUserThrows() {
        String userId = "validId";
        when(mockScimUserProvisioning.retrieve(userId, currentZoneId))
                .thenThrow(new ScimResourceNotFoundException("So sad"));
        assertThat(subject.getUser(userId)).isNull();
    }

    @Test
    void shouldConstructEmailBasedOnUsernameIfNoEmailList() {
        ScimUser scimUser = scimUserFrom("userName", null);
        assertThat(subject.getEmail(scimUser)).isEqualTo("userName@%s".formatted(DEFAULT_EMAIL_DOMAIN));
    }

    @Test
    void shouldNotConstructEmailBasedOnUsernameIfNoEmailListAndTheUsernameContainsAnAtSymbol() {
        ScimUser scimUser = scimUserFrom("userName@", null);
        assertThat(subject.getEmail(scimUser)).isEqualTo("userName@");
    }

    @Test
    void shouldConstructEmailBasedOnUsernameIfEmailListIsEmpty() {
        ScimUser scimUser = scimUserFrom("userName", Collections.emptyList());
        assertThat(subject.getEmail(scimUser)).isEqualTo("userName@%s".formatted(DEFAULT_EMAIL_DOMAIN));
    }

    @Test
    void shouldConstructEmailBasedOnUsernameIfEmailListIsEmptyAndTheUsernameContainsAnAtSymbol() {
        ScimUser scimUser = scimUserFrom("userName@", Collections.emptyList());
        assertThat(subject.getEmail(scimUser)).isEqualTo("userName@");
    }

    @Test
    void shouldReturnFirstEmailFromEmailListIfNoPrimary() {
        ScimUser scimUser = scimUserFrom("userName", Arrays.asList("a@example.com", "b@example.com"));
        assertThat(subject.getEmail(scimUser)).isEqualTo("a@example.com");
    }

    @Test
    void shouldReturnFirstPrimaryEmail() {
        ScimUser scimUser = scimUserFrom("userName", Arrays.asList("a@example.com", "b@example.com", "c@example.com"));
        scimUser.getEmails().get(1).setPrimary(true);
        assertThat(subject.getEmail(scimUser)).isEqualTo("b@example.com");
    }

    @Test
    void notAuthenticatedReturnsSystemAuth() {
        assertThat(subject.getPrincipal()).isSameAs(authentication);
        SecurityContextHolder.clearContext();
        assertThat(subject.getPrincipal()).isSameAs(SystemAuthentication.SYSTEM_AUTHENTICATION);
    }

    private ScimUser scimUserFrom(String userName, List<String> emailAddresses) {
        ScimUser scimUser = new ScimUser(userName, userName, userName, userName);
        if (emailAddresses != null) {
            List<ScimUser.Email> emails = emailAddresses.stream().map(emailAddress -> {
                ScimUser.Email email = new ScimUser.Email();
                email.setValue(emailAddress);
                return email;
            }).toList();

            scimUser.setEmails(emails);
        }
        return scimUser;
    }
}
