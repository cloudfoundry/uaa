package org.cloudfoundry.identity.uaa.oauth.client;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientDetailsCreation extends BaseClientDetails {

    @JsonProperty("secondary_client_secret")
    private String secondaryClientSecret;

    @JsonIgnore
    public String getSecondaryClientSecret() {
        return secondaryClientSecret;
    }

    public void setSecondaryClientSecret(final String secondaryClientSecret) {
        this.secondaryClientSecret = secondaryClientSecret;
    }
}
