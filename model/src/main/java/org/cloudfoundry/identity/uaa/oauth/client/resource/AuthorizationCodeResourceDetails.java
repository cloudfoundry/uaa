package org.cloudfoundry.identity.uaa.oauth.client.resource;

public class AuthorizationCodeResourceDetails extends AbstractRedirectResourceDetails {
  public AuthorizationCodeResourceDetails() {
    this.setGrantType("authorization_code");
  }
}