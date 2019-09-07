package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_EMPTY)
@Data
public class LostPasswordChangeRequest {

    @JsonProperty("code")
    private String changeCode;

    @JsonProperty("new_password")
    private String newPassword;
}
