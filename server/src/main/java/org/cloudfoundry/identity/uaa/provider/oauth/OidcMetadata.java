package org.cloudfoundry.identity.uaa.provider.oauth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URL;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OidcMetadata {
    @JsonProperty("authorization_endpoint")
    private URL authorizationEndpoint;

    @JsonProperty("userinfo_endpoint")
    private URL userinfoEndpoint;

    @JsonProperty("token_endpoint")
    private URL tokenEndpoint;

    @JsonProperty("jwks_uri")
    private URL jsonWebKeysUri;

    @JsonProperty("end_session_endpoint")
    private URL logoutEndpoint;

    private String issuer;

    public URL getAuthorizationEndpoint() {
        return authorizationEndpoint;
    }

    public void setAuthorizationEndpoint(URL authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
    }

    public URL getUserinfoEndpoint() {
        return userinfoEndpoint;
    }

    public void setUserinfoEndpoint(URL userinfoEndpoint) {
        this.userinfoEndpoint = userinfoEndpoint;
    }

    public URL getTokenEndpoint() {
        return tokenEndpoint;
    }

    public void setTokenEndpoint(URL tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
    }

    public URL getJsonWebKeysUri() {
        return jsonWebKeysUri;
    }

    public void setJsonWebKeysUri(URL jsonWebKeysUri) {
        this.jsonWebKeysUri = jsonWebKeysUri;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public URL getLogoutEndpoint() {
        return this.logoutEndpoint;
    }

    public void setLogoutEndpoint(URL logoutEndpoint) {
        this.logoutEndpoint = logoutEndpoint;
    }
}
