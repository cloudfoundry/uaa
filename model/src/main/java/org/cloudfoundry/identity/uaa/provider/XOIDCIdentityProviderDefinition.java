package org.cloudfoundry.identity.uaa.provider;

import java.net.URL;

public class XOIDCIdentityProviderDefinition extends AbstractXOAuthIdentityProviderDefinition<XOIDCIdentityProviderDefinition> {

    private URL userInfoUrl;

    public URL getUserInfoUrl() {
        return userInfoUrl;
    }

    public XOIDCIdentityProviderDefinition setUserInfoUrl(URL userInfoUrl) {
        this.userInfoUrl = userInfoUrl;
        return this;
    }
}
