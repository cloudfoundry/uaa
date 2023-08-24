package org.cloudfoundry.identity.uaa.oauth.client;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import static org.cloudfoundry.identity.uaa.oauth.client.ClientJwtChangeRequest.ChangeMode.ADD;

/**
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientJwtChangeRequest {

    public enum ChangeMode {
        UPDATE,
        ADD,
        DELETE
    }
    @JsonProperty("kid")
    private String keyId;
    @JsonProperty("jwks_uri")
    private String jsonWebKeyUri;
    @JsonProperty("jwks")
    private String jsonWebKeySet;
    @JsonProperty("client_id")
    private String clientId;
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

    public String getKeyId() { return keyId;}

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getKey() {
        return jsonWebKeyUri != null ? jsonWebKeyUri : jsonWebKeySet;
    }
}
