package org.cloudfoundry.identity.uaa.oauth.beans;

import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.AfterThrowing;
import org.aspectj.lang.annotation.Aspect;
import org.cloudfoundry.identity.uaa.client.ClientAuthenticationPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Aspect
@Component
class ClientAuthenticationAopConfig {

    private final ClientAuthenticationPublisher clientAuthenticationPublisher;

    ClientAuthenticationAopConfig(ClientAuthenticationPublisher clientAuthenticationPublisher) {
        this.clientAuthenticationPublisher = clientAuthenticationPublisher;
    }

    @AfterReturning(pointcut="execution(* *..ProviderManager+.authenticate(..)) && bean(clientAuthenticationManager)", returning="authentication")
    public void clientAuthenticationSuccess(
            Authentication authentication
    ) {
        clientAuthenticationPublisher.clientAuthenticationSuccess(authentication);
    }

    @AfterThrowing(pointcut="execution(* *..ProviderManager+.authenticate(..)) && args(authentication) && bean(clientAuthenticationManager)", throwing = "exception")
    public void clientAuthenticationFailure(
            Authentication authentication,
            AuthenticationException exception
    ) {
        clientAuthenticationPublisher.clientAuthenticationFailure(authentication, exception);
    }

}
