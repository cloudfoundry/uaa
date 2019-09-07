package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class EmailChange {
    private String userId;
    private String email;

    @JsonProperty("client_id")
    private String clientId;
}
