package org.cloudfoundry.identity.uaa.oauth;

import java.net.URISyntaxException;
import java.net.URL;
import org.cloudfoundry.identity.uaa.util.UaaTokenUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

public class TokenEndpointBuilder {

  private static final Logger logger = LoggerFactory.getLogger(TokenEndpointBuilder.class);
  private final String issuer;

  public TokenEndpointBuilder(@Value("${issuer.uri}") final String issuerUrlBase) throws Exception {
    new URL(issuerUrlBase); // validate issuer url is valid
    this.issuer = issuerUrlBase;
  }

  public String getTokenEndpoint(final IdentityZone identityZone) {
    try {
      return UaaTokenUtils.constructTokenEndpointUrl(issuer, identityZone);
    } catch (URISyntaxException e) {
      logger.error("Failed to get token endpoint for issuer " + issuer, e);
      throw new IllegalArgumentException(e);
    }
  }
}
