package org.cloudfoundry.identity.uaa.mfa_provider;

import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import com.warrenstrange.googleauth.IGoogleAuthenticator;

public class GoogleAuthenticatorAdapter {
    public String getOtpAuthURL(IGoogleAuthenticator authenticator, String userId, String userName) {
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL("UAA", userName, authenticator.createCredentials(userId));
    }
}
