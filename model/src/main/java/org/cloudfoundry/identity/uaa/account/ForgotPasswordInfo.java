package org.cloudfoundry.identity.uaa.account;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ForgotPasswordInfo {
    private String userId;
    private String email;
    private ExpiringCode resetPasswordCode;
}
