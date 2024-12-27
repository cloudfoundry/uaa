package org.cloudfoundry.identity.uaa.oauth.refresh;

import java.util.Date;
import java.util.Map;
import java.util.Set;

public class RefreshTokenRequestData {
    public final String grantType;
    public final Set<String> scopes;
    public final Set<String> authenticationMethods;
    public final String authorities;
    public final Set<String> resourceIds;
    public final String clientId;
    public final boolean revocable;
    public final Date authTime;
    public final Set<String> acr;
    public final Map<String, Object> externalAttributes;

    public RefreshTokenRequestData(String grantType,
            Set<String> scopes,
            Set<String> authenticationMethods,
            String authorities,
            Set<String> resourceIds,
            String clientId,
            boolean revocable,
            Date authTime,
            Set<String> acr,
            Map<String, Object> externalAttributes) {
        this.grantType = grantType;
        this.scopes = scopes;
        this.authenticationMethods = authenticationMethods;
        this.authorities = authorities;
        this.resourceIds = resourceIds;
        this.clientId = clientId;
        this.revocable = revocable;
        this.authTime = authTime;
        this.acr = acr;
        this.externalAttributes = externalAttributes;
    }

}
