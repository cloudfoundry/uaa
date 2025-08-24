package org.cloudfoundry.identity.uaa.oauth.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import static org.cloudfoundry.identity.uaa.oauth.client.ClientJwtChangeRequest.ChangeMode.ADD;
import static org.cloudfoundry.identity.uaa.oauth.client.ClientJwtChangeRequest.ChangeMode.DELETE;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientJwtChangeRequest {

    public static final String JWKS_URI = "jwks_uri";
    public static final String JWKS = "jwks";
    public static final String ISS = "iss";
    public static final String SUB = "sub";
    public static final String AUD = "aud";

    public enum ChangeMode {
        UPDATE,
        ADD,
        DELETE
    }
    @JsonProperty("kid")
    private String keyId;
    @JsonProperty(JWKS_URI)
    private String jsonWebKeyUri;
    @JsonProperty(JWKS)
    private String jsonWebKeySet;
    @JsonProperty("client_id")
    private String clientId;
    @JsonProperty(ISS)
    private String issuer;
    @JsonProperty(SUB)
    private String subject;
    @JsonProperty(AUD)
    private String audience;

    private ChangeMode changeMode = ADD;

    public ClientJwtChangeRequest() {
    }

    public ClientJwtChangeRequest(String clientId, String jsonWebKeyUri, String jsonWebKeySet) {
        this.jsonWebKeyUri = jsonWebKeyUri;
        this.jsonWebKeySet = jsonWebKeySet;
        this.clientId = clientId;
    }

    public String getJsonWebKeyUri() {
        return jsonWebKeyUri;
    }

    public void setJsonWebKeyUri(String jsonWebKeyUri) {
        this.jsonWebKeyUri = jsonWebKeyUri;
    }

    public String getJsonWebKeySet() {
        return jsonWebKeySet;
    }

    public void setJsonWebKeySet(String jsonWebKeySet) {
        this.jsonWebKeySet = jsonWebKeySet;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public ChangeMode getChangeMode() {
        return changeMode;
    }

    public void setChangeMode(ChangeMode changeMode) {
        this.changeMode = changeMode;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getIssuer() {
        return this.issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return this.subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getAudience() {
        return this.audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getChangeValue() {
        // Depending on change mode, allow different values
        if (changeMode == DELETE && keyId != null) {
            return keyId;
        }
        return jsonWebKeyUri != null ? jsonWebKeyUri : jsonWebKeySet;
    }

    @JsonIgnore
    public boolean isFederated() {
        // private_key_jwt according to RFC 7523. audience is addition supported, but optional
        return issuer != null && subject != null;
    }

    @JsonIgnore
    public ClientJwtCredential getFederation() {
        return new ClientJwtCredential(subject, issuer, audience);
    }
}
