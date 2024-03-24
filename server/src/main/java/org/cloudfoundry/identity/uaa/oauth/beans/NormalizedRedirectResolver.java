package org.cloudfoundry.identity.uaa.oauth.beans;

import static org.cloudfoundry.identity.uaa.util.UaaUrlUtils.normalizeUri;

public class NormalizedRedirectResolver extends UaaDefaultRedirectResolver {
    @Override
    protected boolean redirectMatches(String requestedRedirect, String clientRedirect) {
        return super.redirectMatches(normalizeUri(requestedRedirect),
                normalizeUri(clientRedirect));
    }
}
