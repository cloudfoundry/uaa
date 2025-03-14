package org.cloudfoundry.identity.uaa.client;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.cloudfoundry.identity.uaa.client.event.ClientAdminEventPublisher;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.stereotype.Component;

@Aspect
@Component
class ClientAopConfig {

    private final ClientAdminEventPublisher clientAdminEventPublisher;

    ClientAopConfig(ClientAdminEventPublisher clientAdminEventPublisher) {
        this.clientAdminEventPublisher = clientAdminEventPublisher;
    }

    @Around("execution(* *..ClientAdminEndpoints+.removeClientDetails(String, ..)) and args(clientId,..) and bean(clientAdminEndpoints))")
    public ClientDetails delete(ProceedingJoinPoint joinPoint, String clientId) throws Throwable {
        return clientAdminEventPublisher.delete(joinPoint, clientId);
    }

    @AfterThrowing(pointcut = "execution(* *..ClientAdminEndpoints+.changeClientJwt(String, ..)) and args(clientId,..) and bean(clientAdminEndpoints)", throwing = "exception")
    public void clientJwtChange(String clientId, Exception exception) {
        clientAdminEventPublisher.clientJwtFailure(clientId, exception);
    }

    @AfterThrowing(pointcut = "execution(* *..ClientAdminEndpoints+.changeSecret(String, ..)) and args(clientId,..) and bean(clientAdminEndpoints)", throwing = "exception")
    public void secretChange(String clientId, Exception exception) {
        clientAdminEventPublisher.secretFailure(clientId, exception);
    }

    @AfterReturning(pointcut = "execution(* *..ClientAdminEndpoints+.changeClientJwt(String, ..)) and args(clientId,..) and bean(clientAdminEndpoints)")
    public void clientJwtChange(String clientId) {
        clientAdminEventPublisher.clientJwtChange(clientId);
    }

    @AfterReturning(pointcut = "execution(* *..ClientAdminEndpoints+.changeSecret(String, ..)) and args(clientId,..) and bean(clientAdminEndpoints)")
    public void secretChange(String clientId) {
        clientAdminEventPublisher.secretChange(clientId);
    }

    @AfterReturning(pointcut = "execution(* *..ClientAdminEndpoints+.createClientDetails(..)) and bean(clientAdminEndpoints)", returning = "client")
    public void create(ClientDetails client) {
        clientAdminEventPublisher.create(client);
    }

    @AfterReturning(pointcut = "execution(* *..ClientAdminEndpoints+.updateClientDetails(..)) and bean(clientAdminEndpoints)", returning = "client")
    public void update(ClientDetails client) {
        clientAdminEventPublisher.update(client);
    }

    @AfterReturning(pointcut = "execution(* *..ClientAdminEndpoints+.createClientDetailsTx(..)) and bean(clientAdminEndpoints)", returning = "clients")
    public void createTx(ClientDetails[] clients) {
        clientAdminEventPublisher.createTx(clients);
    }

    @AfterReturning(pointcut = "execution(* *..ClientAdminEndpoints+.updateClientDetailsTx(..)) and bean(clientAdminEndpoints)", returning = "clients")
    public void updateTx(ClientDetails[] clients) {
        clientAdminEventPublisher.updateTx(clients);
    }

    @AfterReturning(pointcut = "execution(* *..ClientAdminEndpoints+.removeClientDetailsTx(..)) and bean(clientAdminEndpoints)", returning = "clients")
    public void deleteTx(ClientDetails[] clients) {
        clientAdminEventPublisher.deleteTx(clients);
    }

    @AfterReturning(pointcut = "execution(* *..ClientAdminEndpoints+.modifyClientDetailsTx(..)) and bean(clientAdminEndpoints)", returning = "clients")
    public void modifyTx(ClientDetailsModification[] clients) {
        clientAdminEventPublisher.modifyTx(clients);
    }

    @AfterReturning(pointcut = "execution(* *..ClientAdminEndpoints+.changeSecretTx(..)) and bean(clientAdminEndpoints)", returning = "clients")
    public void secretTx(ClientDetailsModification[] clients) {
        clientAdminEventPublisher.secretTx(clients);
    }
}
