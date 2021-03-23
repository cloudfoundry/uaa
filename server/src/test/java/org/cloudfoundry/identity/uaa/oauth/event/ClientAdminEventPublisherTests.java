package org.cloudfoundry.identity.uaa.oauth.event;

import org.aspectj.lang.ProceedingJoinPoint;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.client.event.*;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;

import static org.mockito.Mockito.*;

class ClientAdminEventPublisherTests {

    private MultitenantClientServices mockMultitenantClientServices;
    private ApplicationEventPublisher mockApplicationEventPublisher;
    private ClientAdminEventPublisher subject;

    @BeforeEach
    void setUp() {
        mockMultitenantClientServices = mock(MultitenantClientServices.class);
        subject = new ClientAdminEventPublisher(mockMultitenantClientServices, mock(IdentityZoneManager.class));
        mockApplicationEventPublisher = mock(ApplicationEventPublisher.class);

        subject.setApplicationEventPublisher(mockApplicationEventPublisher);
        OAuth2Request oAuth2Request = new AuthorizationRequest("client", Collections.singletonList("read")).createOAuth2Request();
        UaaAuthentication authentication1 = UaaAuthenticationTestFactory.getAuthentication("ID", "joe", "joe@test.org");
        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, authentication1);
        SecurityContextHolder.getContext().setAuthentication(oAuth2Authentication);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void create() {
        BaseClientDetails client = new BaseClientDetails("foo", null, null, "client_credentials", "none");
        subject.create(client);
        verify(mockApplicationEventPublisher).publishEvent(isA(ClientCreateEvent.class));
    }

    @Test
    void update() {
        BaseClientDetails client = new BaseClientDetails("foo", null, null, "client_credentials", "none");
        subject.update(client);
        verify(mockApplicationEventPublisher).publishEvent(isA(ClientUpdateEvent.class));
    }

    @Test
    void delete() throws Throwable {
        BaseClientDetails client = new BaseClientDetails("foo", null, null, "client_credentials", "none");
        ProceedingJoinPoint jp = mock(ProceedingJoinPoint.class);
        when(jp.proceed()).thenReturn(client);
        subject.delete(jp, "foo");
        verify(mockApplicationEventPublisher).publishEvent(isA(ClientDeleteEvent.class));
    }

    @Test
    void secretChange() {
        when(mockMultitenantClientServices.loadClientByClientId("foo")).thenReturn(
                new BaseClientDetails("foo", null, null, "client_credentials", "none"));
        subject.secretChange("foo");
        verify(mockApplicationEventPublisher).publishEvent(isA(SecretChangeEvent.class));
    }

    @Test
    void secretFailure() {
        when(mockMultitenantClientServices.loadClientByClientId("foo")).thenReturn(
                new BaseClientDetails("foo", null, null, "client_credentials", "none"));
        subject.secretFailure("foo", new RuntimeException("planned"));
        verify(mockApplicationEventPublisher).publishEvent(isA(SecretFailureEvent.class));
    }

    @Test
    void secretFailureMissingClient() {
        when(mockMultitenantClientServices.loadClientByClientId("foo")).thenThrow(
                new InvalidClientException("Not found"));
        subject.secretFailure("foo", new RuntimeException("planned"));
        verify(mockApplicationEventPublisher).publishEvent(isA(SecretFailureEvent.class));
    }
}
