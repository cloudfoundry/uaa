package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.authentication.event.ClientAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.ClientAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public class ClientAuthenticationPublisher implements ApplicationEventPublisherAware {

  private ApplicationEventPublisher publisher;

  @Override
  public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
    this.publisher = publisher;
  }

  public void clientAuthenticationSuccess(Authentication authentication) {
    publish(
        new ClientAuthenticationSuccessEvent(
            authentication, IdentityZoneHolder.getCurrentZoneId()));
  }

  public void clientAuthenticationFailure(
      Authentication authentication, AuthenticationException ex) {
    publish(
        new ClientAuthenticationFailureEvent(
            authentication, ex, IdentityZoneHolder.getCurrentZoneId()));
  }

  public void publish(ApplicationEvent event) {
    if (publisher != null) {
      publisher.publishEvent(event);
    }
  }
}
