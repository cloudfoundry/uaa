package org.cloudfoundry.identity.uaa.client;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.util.Assert;

/** @author Dave Syer */
public class OAuth2AccessTokenSource
    implements InitializingBean, PreAuthenticatedPrincipalSource<String> {

  private OAuth2RestOperations restTemplate;

  /**
   * A rest template to be used to contact the remote user info endpoint. Normally an instance of
   * {@link OAuth2RestTemplate}.
   *
   * @param restTemplate a rest template
   */
  public void setRestTemplate(OAuth2RestOperations restTemplate) {
    this.restTemplate = restTemplate;
  }

  @Override
  public void afterPropertiesSet() {
    Assert.state(restTemplate != null, "RestTemplate URL must be provided");
  }

  @Override
  public String getPrincipal() {
    return restTemplate.getAccessToken().getValue();
  }
}
