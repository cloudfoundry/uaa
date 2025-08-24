package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.oauth.provider.endpoint.DefaultRedirectResolver;

import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.normalizeUri;

public class NormalizedRedirectResolver extends DefaultRedirectResolver {
    @Override
    protected boolean redirectMatches(String requestedRedirect, String clientRedirect) {
        return super.redirectMatches(normalizeUri(requestedRedirect),
                normalizeUri(clientRedirect));
    }
}
