package org.cloudfoundry.identity.uaa.account.event;

import org.cloudfoundry.identity.uaa.account.UaaPasswordTestFactory;
import org.cloudfoundry.identity.uaa.authentication.SystemAuthentication;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.ScimUserTestFactory;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;

class PasswordChangeEventPublisherTests {

    private ScimUserProvisioning scimUserProvisioning = Mockito.mock(ScimUserProvisioning.class);

    private PasswordChangeEventPublisher subject = new PasswordChangeEventPublisher(scimUserProvisioning);

    private ApplicationEventPublisher publisher = Mockito.mock(ApplicationEventPublisher.class);
    private Authentication authentication;

    @BeforeEach
    void init() {
        subject.setApplicationEventPublisher(publisher);
        authentication = new OAuth2Authentication(
                new AuthorizationRequest(
                        "client",
                        Collections.singletonList("read")).createOAuth2Request(),
                UaaPasswordTestFactory.getAuthentication("ID", "joe", "joe@test.org")
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @AfterEach
    void destroy() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void passwordChange() {
        when(scimUserProvisioning.retrieve("foo", IdentityZoneHolder.get().getId())).thenReturn(
                ScimUserTestFactory.getScimUser("joe", "joe@test.org", "Joe", "Schmo"));
        subject.passwordChange("foo");
        Mockito.verify(publisher).publishEvent(ArgumentMatchers.isA(PasswordChangeEvent.class));
    }

    @Test
    void passwordChangeNoEmail() {
        when(scimUserProvisioning.retrieve("foo", IdentityZoneHolder.get().getId())).thenReturn(
                ScimUserTestFactory.getScimUser("joe", null, "Joe", "Schmo"));
        subject.passwordChange("foo");
        Mockito.verify(publisher).publishEvent(ArgumentMatchers.isA(PasswordChangeEvent.class));
    }

    @Test
    void passwordFailure() {
        when(scimUserProvisioning.retrieve("foo", IdentityZoneHolder.get().getId())).thenReturn(
                ScimUserTestFactory.getScimUser("joe", "joe@test.org", "Joe", "Schmo"));
        subject.passwordFailure("foo", new RuntimeException("planned"));
        Mockito.verify(publisher).publishEvent(ArgumentMatchers.isA(PasswordChangeFailureEvent.class));
    }

    @Test
    void passwordFailureNoUser() {
        when(scimUserProvisioning.retrieve("foo", IdentityZoneHolder.get().getId())).thenThrow(new ScimResourceNotFoundException("Not found"));
        subject.passwordFailure("foo", new RuntimeException("planned"));
        Mockito.verify(publisher).publishEvent(ArgumentMatchers.any(PasswordChangeFailureEvent.class));
    }

    @Test
    void notAuthenticatedReturnsSystemAuth() {
        assertSame(authentication, subject.getPrincipal());
        SecurityContextHolder.clearContext();
        assertSame(SystemAuthentication.SYSTEM_AUTHENTICATION, subject.getPrincipal());
    }
}
