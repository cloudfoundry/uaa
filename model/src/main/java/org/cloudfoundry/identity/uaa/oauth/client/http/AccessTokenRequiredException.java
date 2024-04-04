package org.cloudfoundry.identity.uaa.oauth.client.http;

import org.cloudfoundry.identity.uaa.oauth.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.authentication.InsufficientAuthenticationException;

public class AccessTokenRequiredException extends InsufficientAuthenticationException {

  private final OAuth2ProtectedResourceDetails resource;

  public AccessTokenRequiredException(OAuth2ProtectedResourceDetails resource) {
    super("OAuth2 access denied.");
    this.resource = resource;
  }

  public AccessTokenRequiredException(String msg, OAuth2ProtectedResourceDetails resource) {
    super(msg);
    this.resource = resource;
  }

  public AccessTokenRequiredException(String msg, OAuth2ProtectedResourceDetails resource, Throwable t) {
    super(msg, t);
    this.resource = resource;
  }

  public OAuth2ProtectedResourceDetails getResource() {
    return resource;
  }
}
