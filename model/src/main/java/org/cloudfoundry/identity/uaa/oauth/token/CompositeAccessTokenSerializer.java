package org.cloudfoundry.identity.uaa.oauth.token;

import org.cloudfoundry.identity.uaa.oauth.common.OAuth2AccessTokenJackson2Serializer;

public final class CompositeAccessTokenSerializer extends OAuth2AccessTokenJackson2Serializer {

    public CompositeAccessTokenSerializer() {
        super(CompositeToken.class);
    }
}
