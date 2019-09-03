package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@Data
public class PasswordResetResponse {
    @JsonProperty("code")
    private String changeCode;

    @JsonProperty("user_id")
    private String userId;
}
