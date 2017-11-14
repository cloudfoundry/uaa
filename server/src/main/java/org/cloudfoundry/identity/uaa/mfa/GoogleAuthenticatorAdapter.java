package org.cloudfoundry.identity.uaa.mfa;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;

public class GoogleAuthenticatorAdapter {

    private GoogleAuthenticator authenticator;

    public String getOtpAuthURL(String qrIssuer, String userId, String userName) {
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL(qrIssuer, userName, authenticator.createCredentials(userId));
    }

    public boolean isValidCode(String userId, Integer code) {
        return authenticator.authorizeUser(userId, code);
    }

    public void setAuthenticator(GoogleAuthenticator authenticator) {
        this.authenticator = authenticator;
    }
}
