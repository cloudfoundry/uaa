package org.cloudfoundry.identity.uaa.oauth.event;

import org.aspectj.lang.ProceedingJoinPoint;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.client.event.ClientAdminEventPublisher;
import org.cloudfoundry.identity.uaa.client.event.ClientCreateEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientDeleteEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientJwtChangeEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientJwtFailureEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientUpdateEvent;
import org.cloudfoundry.identity.uaa.client.event.SecretChangeEvent;
import org.cloudfoundry.identity.uaa.client.event.SecretFailureEvent;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
        UaaClientDetails client = new UaaClientDetails("foo", null, null, "client_credentials", "none");
        subject.create(client);
        verify(mockApplicationEventPublisher).publishEvent(isA(ClientCreateEvent.class));
    }

    @Test
    void update() {
        UaaClientDetails client = new UaaClientDetails("foo", null, null, "client_credentials", "none");
        subject.update(client);
        verify(mockApplicationEventPublisher).publishEvent(isA(ClientUpdateEvent.class));
    }

    @Test
    void delete() throws Throwable {
        UaaClientDetails client = new UaaClientDetails("foo", null, null, "client_credentials", "none");
        ProceedingJoinPoint jp = mock(ProceedingJoinPoint.class);
        when(jp.proceed()).thenReturn(client);
        subject.delete(jp, "foo");
        verify(mockApplicationEventPublisher).publishEvent(isA(ClientDeleteEvent.class));
    }

    @Test
    void secretChange() {
        when(mockMultitenantClientServices.loadClientByClientId("foo")).thenReturn(
                new UaaClientDetails("foo", null, null, "client_credentials", "none"));
        subject.secretChange("foo");
        verify(mockApplicationEventPublisher).publishEvent(isA(SecretChangeEvent.class));
    }

    @Test
    void secretFailure() {
        when(mockMultitenantClientServices.loadClientByClientId("foo")).thenReturn(
                new UaaClientDetails("foo", null, null, "client_credentials", "none"));
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

    @Test
    void clientJwtChange() {
        UaaClientDetails uaaUaaClientDetails = new UaaClientDetails("foo", null, null, "client_credentials", "none", null);
        when(mockMultitenantClientServices.loadClientByClientId("foo")).thenReturn(uaaUaaClientDetails);
        subject.clientJwtChange("foo");
        verify(mockApplicationEventPublisher).publishEvent(isA(ClientJwtChangeEvent.class));
        assertThat(new ClientJwtChangeEvent(uaaUaaClientDetails, SecurityContextHolder.getContext().getAuthentication(), "uaa").getAuditEvent().getType()).isEqualTo(AuditEventType.ClientJwtChangeSuccess);
    }

    @Test
    void clientJwtFailure() {
        UaaClientDetails uaaUaaClientDetails = new UaaClientDetails("foo", null, null, "client_credentials", "none", null);
        when(mockMultitenantClientServices.loadClientByClientId("foo")).thenReturn(uaaUaaClientDetails);
        subject.clientJwtFailure("foo", new RuntimeException("planned"));
        verify(mockApplicationEventPublisher).publishEvent(isA(ClientJwtFailureEvent.class));
        assertThat(new ClientJwtFailureEvent("", uaaUaaClientDetails, SecurityContextHolder.getContext().getAuthentication(), "uaa").getAuditEvent().getType()).isEqualTo(AuditEventType.ClientJwtChangeFailure);
    }
}
