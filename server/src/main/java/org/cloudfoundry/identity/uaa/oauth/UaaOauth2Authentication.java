package org.cloudfoundry.identity.uaa.oauth;


import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

public class UaaOauth2Authentication extends OAuth2Authentication {

    private final String zoneId;
    private final String tokenValue;

    public UaaOauth2Authentication(String tokenValue, String zoneId, OAuth2Request storedRequest, Authentication userAuthentication) {
        super(storedRequest, userAuthentication);
        this.zoneId = zoneId;
        this.tokenValue = tokenValue;
    }

    public String getZoneId() {
        return zoneId;
    }

    public String getTokenValue() {
        return tokenValue;
    }
}
