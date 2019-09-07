package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@Data
public class LostPasswordChangeResponse {

    @JsonProperty("code")
    private String loginCode;

    @JsonProperty("user_id")
    private String userId;

    private String username;
    private String email;

}
