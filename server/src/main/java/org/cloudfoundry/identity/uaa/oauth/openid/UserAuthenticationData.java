package org.cloudfoundry.identity.uaa.oauth.openid;

import org.springframework.util.MultiValueMap;

import java.util.Date;
import java.util.Set;

public class UserAuthenticationData {
    public final Date time;
    public final Set<String> methods;
    public final Set<String> contextClassRef;
    public final Set<String> scopes;
    public final Set<String> roles;
    public final MultiValueMap<String, String> userAttributes;

    public UserAuthenticationData(Date time,
                                  Set<String> methods,
                                  Set<String> contextClassRef,
                                  Set<String> scopes,
                                  Set<String> roles,
                                  MultiValueMap<String, String> userAttributes) {
        this.time = time;
        this.methods = methods;
        this.contextClassRef = contextClassRef;
        this.scopes = scopes;
        this.roles = roles;
        this.userAttributes = userAttributes;
    }
}

