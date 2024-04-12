package org.cloudfoundry.identity.uaa.oauth.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientDetailsCreation extends UaaClientDetails {

    @JsonProperty("secondary_client_secret")
    private String secondaryClientSecret;

    @JsonProperty("jwks_uri")
    private String jsonWebKeyUri;

    @JsonProperty("jwks")
    private String jsonWebKeySet;

    @JsonIgnore
    public String getSecondaryClientSecret() {
        return secondaryClientSecret;
    }

    public void setSecondaryClientSecret(final String secondaryClientSecret) {
        this.secondaryClientSecret = secondaryClientSecret;
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
}
