package org.cloudfoundry.identity.uaa.oauth;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class OauthGrant {
    
    public static final String CLIENT_CREDENTIALS = "client_credentials";
    public static final String PASSWORD = "password";
    public static final String IMPLICIT = "implicit";
    public static final String AUTHORIZATION_CODE = "authorization_code";
    public static final String REFRESH_TOKEN = "refresh_token";
    public static final String JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer";
    
    public static final Set<String> SUPPORTED_GRANTS =  
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
                    CLIENT_CREDENTIALS, PASSWORD, IMPLICIT, AUTHORIZATION_CODE, REFRESH_TOKEN, JWT_BEARER)));
}
