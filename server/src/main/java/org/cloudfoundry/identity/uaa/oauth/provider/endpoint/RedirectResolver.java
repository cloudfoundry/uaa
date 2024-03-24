package org.cloudfoundry.identity.uaa.oauth.provider.endpoint;

import org.cloudfoundry.identity.uaa.oauth.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.ClientDetails;

public interface RedirectResolver {

  /**
   * Resolve the redirect for the specified client.
   *
   * @param requestedRedirect The redirect that was requested (may not be null).
   * @param client The client for which we're resolving the redirect.
   * @return The resolved redirect URI.
   * @throws OAuth2Exception If the requested redirect is invalid for the specified client.
   */
  String resolveRedirect(String requestedRedirect, ClientDetails client) throws OAuth2Exception;
}
