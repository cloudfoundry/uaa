package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.event.PrincipalAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.PrincipalNotFoundEvent;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

/**
 * Spring {@code ApplicationListener} which picks up the listens for Spring
 * Security events and relays them.
 *
 * @author Dave Syer
 */
@Component
public class BadCredentialsListener
        implements ApplicationListener<AuthenticationFailureBadCredentialsEvent>,
        ApplicationEventPublisherAware {

    private final IdentityZoneManager identityZoneManager;

    private ApplicationEventPublisher publisher;

    public BadCredentialsListener(IdentityZoneManager identityZoneManager) {
        this.identityZoneManager = identityZoneManager;
    }

    @Override
    public void setApplicationEventPublisher(@NonNull final ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent event) {
        String principal = event.getAuthentication().getName();
        UaaAuthenticationDetails details = (UaaAuthenticationDetails) event.getAuthentication().getDetails();
        if (event.getException() instanceof UsernameNotFoundException) {
            publisher.publishEvent(new PrincipalNotFoundEvent(principal, details, identityZoneManager.getCurrentIdentityZoneId()));
        } else {
            publisher.publishEvent(new PrincipalAuthenticationFailureEvent(principal, details, identityZoneManager.getCurrentIdentityZoneId()));
        }
    }

}
