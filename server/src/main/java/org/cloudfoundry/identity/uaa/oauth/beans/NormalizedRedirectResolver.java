package org.cloudfoundry.identity.uaa.oauth.beans;

import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.normalizeUri;

import org.springframework.security.oauth2.provider.endpoint.DefaultRedirectResolver;

public class NormalizedRedirectResolver extends DefaultRedirectResolver {

  @Override
  protected boolean redirectMatches(String requestedRedirect, String clientRedirect) {
    return super.redirectMatches(normalizeUri(requestedRedirect), normalizeUri(clientRedirect));
  }
}
