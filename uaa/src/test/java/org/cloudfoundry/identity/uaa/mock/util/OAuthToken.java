package org.cloudfoundry.identity.uaa.mock.util;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class OAuthToken {
    @JsonProperty("access_token")
    public String accessToken;

    public OAuthToken() {
    }
}
