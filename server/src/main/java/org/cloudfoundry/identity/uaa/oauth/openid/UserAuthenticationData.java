package org.cloudfoundry.identity.uaa.oauth.openid;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class UserAuthenticationData {
    public final Date authTime;
    public final Set<String> authenticationMethods;
    public final Set<String> contextClassRef;
    public final Set<String> scopes;
    public final Set<String> roles;
    public final Map<String, List<String>> userAttributes;
    public final String nonce;
    public final String grantType;
    public final String clientAuth;
    public final String jti;

    public UserAuthenticationData(Date authTime,
            Set<String> authenticationMethods,
            Set<String> contextClassRef,
            Set<String> scopes,
            Set<String> roles,
            Map<String, List<String>> userAttributes,
            String nonce,
            String grantType,
            String clientAuth,
            String jti) {
        this.authTime = authTime;
        this.authenticationMethods = authenticationMethods;
        this.contextClassRef = contextClassRef;
        this.scopes = scopes;
        this.roles = roles;
        this.userAttributes = userAttributes;
        this.nonce = nonce;
        this.grantType = grantType;
        this.clientAuth = clientAuth;
        this.jti = jti;
    }
}

