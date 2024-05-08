package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessTokenJackson2Deserializer;

public final class CompositeAccessTokenDeserializer extends OAuth2AccessTokenJackson2Deserializer {

    public CompositeAccessTokenDeserializer() {
        super(CompositeToken.class);
    }
}
