package org.cloudfoundry.identity.uaa.oauth.client;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import static org.cloudfoundry.identity.uaa.oauth.client.PrivateKeyChangeRequest.ChangeMode.ADD;

/**
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class PrivateKeyChangeRequest {

    public enum ChangeMode {
        UPDATE,
        ADD,
        DELETE
    }
    @JsonProperty("kid")
    private String keyId;
    @JsonProperty("jwks_uri")
    private String keyUrl;
    @JsonProperty("jwks")
    private String keyConfig;
    @JsonProperty("client_id")
    private String clientId;
    private ChangeMode changeMode = ADD;

    public PrivateKeyChangeRequest() {
    }

    public PrivateKeyChangeRequest(String clientId, String keyUrl, String keyConfig) {
        this.keyUrl = keyUrl;
        this.keyConfig = keyConfig;
        this.clientId = clientId;
    }

    public String getKeyUrl() {
        return keyUrl;
    }

    public void setKeyUrl(String keyUrl) {
        this.keyUrl = keyUrl;
    }

    public String getKeyConfig() {
        return keyConfig;
    }

    public void setKeyConfig(String keyConfig) {
        this.keyConfig = keyConfig;
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
        return keyUrl != null ? keyUrl : keyConfig;
    }
}
