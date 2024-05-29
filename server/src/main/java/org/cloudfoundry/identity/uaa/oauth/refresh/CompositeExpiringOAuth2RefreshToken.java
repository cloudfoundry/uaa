package org.cloudfoundry.identity.uaa.oauth.refresh;

import org.cloudfoundry.identity.uaa.oauth.common.DefaultExpiringOAuth2RefreshToken;

import java.util.Date;

public class CompositeExpiringOAuth2RefreshToken extends DefaultExpiringOAuth2RefreshToken {
    private String jti;

    /**
     * @param value
     * @param expiration
     * @param jti
     */
    public CompositeExpiringOAuth2RefreshToken(String value, Date expiration, String jti) {
        super(value, expiration);
        this.jti = jti;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }
}
