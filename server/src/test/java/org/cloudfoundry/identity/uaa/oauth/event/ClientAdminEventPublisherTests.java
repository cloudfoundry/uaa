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

package org.cloudfoundry.identity.uaa.oauth.event;

import org.aspectj.lang.ProceedingJoinPoint;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.client.event.ClientAdminEventPublisher;
import org.cloudfoundry.identity.uaa.client.event.ClientCreateEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientDeleteEvent;
import org.cloudfoundry.identity.uaa.client.event.ClientUpdateEvent;
import org.cloudfoundry.identity.uaa.client.event.SecretChangeEvent;
import org.cloudfoundry.identity.uaa.client.event.SecretFailureEvent;
import org.cloudfoundry.identity.uaa.zone.ClientServicesExtension;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Matchers;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;

/**
 * @author Dave Syer
 *
 */
public class ClientAdminEventPublisherTests {

    private ClientServicesExtension clientDetailsService = Mockito.mock(ClientServicesExtension.class);

    private ClientAdminEventPublisher subject = new ClientAdminEventPublisher(clientDetailsService);

    private ApplicationEventPublisher publisher = Mockito.mock(ApplicationEventPublisher.class);

    @Before
    public void init() {
        subject.setApplicationEventPublisher(publisher);
        Authentication authentication = new OAuth2Authentication(new AuthorizationRequest("client",
                        Arrays.asList("read")).createOAuth2Request(), UaaAuthenticationTestFactory.getAuthentication("ID", "joe",
                        "joe@test.org"));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @After
    public void destroy() {
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testCreate() {
        BaseClientDetails client = new BaseClientDetails("foo", null, null, "client_credentials", "none");
        subject.create(client);
        Mockito.verify(publisher).publishEvent(Matchers.isA(ClientCreateEvent.class));
    }

    @Test
    public void testUpdate() {
        BaseClientDetails client = new BaseClientDetails("foo", null, null, "client_credentials", "none");
        subject.update(client);
        Mockito.verify(publisher).publishEvent(Matchers.isA(ClientUpdateEvent.class));
    }

    @Test
    public void testDelete() throws Throwable {
        BaseClientDetails client = new BaseClientDetails("foo", null, null, "client_credentials", "none");
        ProceedingJoinPoint jp = Mockito.mock(ProceedingJoinPoint.class);
        Mockito.when(jp.proceed()).thenReturn(client);
        subject.delete(jp, "foo");
        Mockito.verify(publisher).publishEvent(Matchers.isA(ClientDeleteEvent.class));
    }

    @Test
    public void testSecretChange() {
        Mockito.when(clientDetailsService.loadClientByClientId("foo")).thenReturn(
                        new BaseClientDetails("foo", null, null, "client_credentials", "none"));
        subject.secretChange("foo");
        Mockito.verify(publisher).publishEvent(Matchers.isA(SecretChangeEvent.class));
    }

    @Test
    public void testSecretFailure() {
        Mockito.when(clientDetailsService.loadClientByClientId("foo")).thenReturn(
                        new BaseClientDetails("foo", null, null, "client_credentials", "none"));
        subject.secretFailure("foo", new RuntimeException("planned"));
        Mockito.verify(publisher).publishEvent(Matchers.isA(SecretFailureEvent.class));
    }

    @Test
    public void testSecretFailureMissingClient() {
        Mockito.when(clientDetailsService.loadClientByClientId("foo")).thenThrow(
                        new InvalidClientException("Not found"));
        subject.secretFailure("foo", new RuntimeException("planned"));
        Mockito.verify(publisher).publishEvent(Matchers.isA(SecretFailureEvent.class));
    }
}
