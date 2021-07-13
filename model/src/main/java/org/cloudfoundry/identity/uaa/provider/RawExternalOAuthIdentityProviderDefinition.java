package org.cloudfoundry.identity.uaa.provider;

import java.net.URL;

public class RawExternalOAuthIdentityProviderDefinition extends AbstractExternalOAuthIdentityProviderDefinition<RawExternalOAuthIdentityProviderDefinition> {

    private URL checkTokenUrl;

    public URL getCheckTokenUrl() {
        return checkTokenUrl;
    }

    public RawExternalOAuthIdentityProviderDefinition setCheckTokenUrl(URL checkTokenUrl) {
        this.checkTokenUrl = checkTokenUrl;
        return this;
    }
}
