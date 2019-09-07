package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class EmailChangeResponse {
    private String username;
    private String userId;
    @JsonProperty("redirect_url")
    private String redirectUrl;
    private String email;
}
