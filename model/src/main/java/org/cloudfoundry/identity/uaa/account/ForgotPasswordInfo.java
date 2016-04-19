package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;

public class ForgotPasswordInfo {
    private String userId;
    private ExpiringCode resetPasswordCode;

    public ForgotPasswordInfo(String userId, ExpiringCode resetPasswordCode) {
        this.userId = userId;
        this.resetPasswordCode = resetPasswordCode;
    }

    public String getUserId() {
        return userId;
    }

    public ExpiringCode getResetPasswordCode() {
        return resetPasswordCode;
    }
}
