package org.cloudfoundry.identity.uaa.oauth.openid;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class UserAuthenticationData {
    public final Date time;
    public final Set<String> methods;
    public final Set<String> contextClassRef;
    public final Set<String> scopes;
    public final Set<String> roles;
    public final Map<String, List<String>> userAttributes;
    public final String nonce;

    public UserAuthenticationData(Date time,
                                  Set<String> methods,
                                  Set<String> contextClassRef,
                                  Set<String> scopes,
                                  Set<String> roles,
                                  Map<String, List<String>> userAttributes,
                                  String nonce) {
        this.time = time;
        this.methods = methods;
        this.contextClassRef = contextClassRef;
        this.scopes = scopes;
        this.roles = roles;
        this.userAttributes = userAttributes;
        this.nonce = nonce;
    }
}

