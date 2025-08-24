package org.cloudfoundry.identity.uaa.zone.beans;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.cloudfoundry.identity.uaa.client.event.ClientAdminEventPublisher;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.DenyAccessToUaaAdvice;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.event.IdentityProviderEventPublisher;
import org.cloudfoundry.identity.uaa.zone.event.IdentityZoneEventPublisher;
import org.springframework.stereotype.Component;

@Aspect
@Component
class IdentityZoneAopConfig {

    private final IdentityZoneEventPublisher identityZoneEventPublisher;
    private final DenyAccessToUaaAdvice denyAccessToUaaAdvice;
    private final ClientAdminEventPublisher clientAdminEventPublisher;
    private final IdentityProviderEventPublisher idpEventPublisher;

    public IdentityZoneAopConfig(IdentityZoneEventPublisher identityZoneEventPublisher, DenyAccessToUaaAdvice denyAccessToUaaAdvice, ClientAdminEventPublisher clientAdminEventPublisher, IdentityProviderEventPublisher idpEventPublisher) {
        this.identityZoneEventPublisher = identityZoneEventPublisher;
        this.denyAccessToUaaAdvice = denyAccessToUaaAdvice;
        this.clientAdminEventPublisher = clientAdminEventPublisher;
        this.idpEventPublisher = idpEventPublisher;
    }

    @AfterReturning(pointcut = "execution(* org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning.create(..))", returning = "identityZone")
    public void identityZoneCreated(IdentityZone identityZone) {
        identityZoneEventPublisher.identityZoneCreated(identityZone);
    }

    @AfterReturning(pointcut = "execution(* org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning.update(..))", returning = "identityZone")
    public void identityZoneModified(IdentityZone identityZone) {
        identityZoneEventPublisher.identityZoneModified(identityZone);
    }

    @Before(value = "execution(* org.cloudfoundry.identity.uaa.zone.IdentityZoneEndpoints.updateIdentityZone(..)) && args(identityZone,identityZoneId)", argNames = "identityZone,identityZoneId")
    public void endpointsUpdateCheckZone(IdentityZone identityZone, String identityZoneId) {
        denyAccessToUaaAdvice.checkIdentityZone(identityZone);
        denyAccessToUaaAdvice.checkIdentityZoneId(identityZoneId);
    }

    @Before(value = "execution(* org.cloudfoundry.identity.uaa.zone.IdentityZoneEndpoints.createClient(..)) && args(identityZoneId,*)", argNames = "identityZoneId")
    public void endpointCreateClient(String identityZoneId) {
        denyAccessToUaaAdvice.checkIdentityZoneId(identityZoneId);
    }

    @Before(value = "execution(* org.cloudfoundry.identity.uaa.zone.IdentityZoneEndpoints.deleteClient(..)) && args(identityZoneId,*)", argNames = "identityZoneId")
    public void endpointDeleteClient(String identityZoneId) {
        denyAccessToUaaAdvice.checkIdentityZoneId(identityZoneId);
    }

    @AfterReturning(pointcut = "execution(* org.cloudfoundry.identity.uaa.zone.IdentityZoneEndpointClientRegistrationService.createClient(..))", returning = "client")
    public void clientCreated(ClientDetails client) {
        clientAdminEventPublisher.create(client);
    }

    @Around(value = "execution(* org.cloudfoundry.identity.uaa.zone.IdentityZoneEndpointClientRegistrationService.deleteClient(..)) && args(clientId)")
    public ClientDetails clientDeleted(ProceedingJoinPoint joinPoint, String clientId) throws Throwable {
        return clientAdminEventPublisher.delete(joinPoint, clientId);
    }

    @AfterReturning(pointcut = "execution(* org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning+.create(..))", returning = "identityProvider")
    public void idpCreated(IdentityProvider identityProvider) {
        idpEventPublisher.idpCreated(identityProvider);
    }

    @AfterReturning(pointcut = "execution(* org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning+.update(..))", returning = "identityProvider")
    public void idpModified(IdentityProvider identityProvider) {
        idpEventPublisher.idpModified(identityProvider);
    }

}