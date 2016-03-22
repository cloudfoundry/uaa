package org.cloudfoundry.identity.uaa.provider;

import java.net.URL;

public class RawXOAuthIdentityProviderDefinition extends AbstractXOAuthIdentityProviderDefinition<RawXOAuthIdentityProviderDefinition> {

    private URL checkTokenUrl;

    public URL getCheckTokenUrl() {
        return checkTokenUrl;
    }

    public RawXOAuthIdentityProviderDefinition setCheckTokenUrl(URL checkTokenUrl) {
        this.checkTokenUrl = checkTokenUrl;
        return this;
    }
}
