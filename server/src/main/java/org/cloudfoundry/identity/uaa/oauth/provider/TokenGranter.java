package org.cloudfoundry.identity.uaa.oauth.provider;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessToken;

public interface TokenGranter {

	OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest);

}
