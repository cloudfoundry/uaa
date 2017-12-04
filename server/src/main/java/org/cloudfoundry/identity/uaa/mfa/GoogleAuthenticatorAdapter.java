package org.cloudfoundry.identity.uaa.mfa;

import com.google.zxing.WriterException;
import com.warrenstrange.googleauth.GoogleAuthenticator;

import java.io.IOException;

public class GoogleAuthenticatorAdapter {

    private GoogleAuthenticator authenticator;

    public String getOtpAuthURL(String qrIssuer, String userId, String userName) throws IOException, WriterException {
        return MfaRegisterQRGenerator.getQRCodePngDataUri(qrIssuer, userName, authenticator.createCredentials(userId));
    }

    public boolean isValidCode(String userId, Integer code) {
        return authenticator.authorizeUser(userId, code);
    }

    public void setAuthenticator(GoogleAuthenticator authenticator) {
        this.authenticator = authenticator;
    }
}
