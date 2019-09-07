package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

@JsonInclude(JsonInclude.Include.NON_NULL)
@Data
public class PasswordChangeRequest {
    private String oldPassword;
    private String password;
}
