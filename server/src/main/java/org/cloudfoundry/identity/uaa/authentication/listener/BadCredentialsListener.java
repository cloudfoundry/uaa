
package org.cloudfoundry.identity.uaa.authentication.listener;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.event.PrincipalAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.PrincipalNotFoundEvent;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.ApplicationListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * Spring {@code ApplicationListener} which picks up the listens for Spring
 * Security events and relays them.
 *
 * @author Dave Syer
 */
public class BadCredentialsListener implements ApplicationListener<AuthenticationFailureBadCredentialsEvent>,
                ApplicationEventPublisherAware {

    private ApplicationEventPublisher publisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @Override
    public void onApplicationEvent(AuthenticationFailureBadCredentialsEvent event) {
        String principal = event.getAuthentication().getName();
        UaaAuthenticationDetails details = (UaaAuthenticationDetails) event.getAuthentication().getDetails();
        if (event.getException() instanceof UsernameNotFoundException) {
            publisher.publishEvent(new PrincipalNotFoundEvent(principal, details, IdentityZoneHolder.getCurrentZoneId()));
        }
        else {
            publisher.publishEvent(new PrincipalAuthenticationFailureEvent(principal, details, IdentityZoneHolder.getCurrentZoneId()));
        }
    }

}
