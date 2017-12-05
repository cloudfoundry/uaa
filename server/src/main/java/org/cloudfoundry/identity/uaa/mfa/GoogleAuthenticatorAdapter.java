package org.cloudfoundry.identity.uaa.mfa;

import com.google.zxing.WriterException;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;

import java.io.IOException;

public class GoogleAuthenticatorAdapter {

    private GoogleAuthenticator authenticator;
    private MfaCredentialsSessionCache credCache;

    public String getOtpAuthURL(String qrIssuer, String userId, String userName) throws IOException, WriterException {
        UserGoogleMfaCredentials credentials = credCache.getCredentials();
        if (credentials == null) {
            GoogleAuthenticatorKey newCredentials = authenticator.createCredentials(userId);
            return MfaRegisterQRGenerator.getQRCodePngDataUri(qrIssuer, userName, newCredentials.getKey());
        } else {
            return MfaRegisterQRGenerator.getQRCodePngDataUri(qrIssuer, userName, credentials.getSecretKey());
        }

    }

    public String getOtpSecret(String userId) {
        UserGoogleMfaCredentials credentials = credCache.getCredentials();
        if (credentials == null) {
            return authenticator.createCredentials(userId).getKey();
        } else {
            return credentials.getSecretKey();
        }
    }

    public boolean isValidCode(String userId, Integer code) {
        return authenticator.authorizeUser(userId, code);
    }

    public void setAuthenticator(GoogleAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    public void setCredCache(MfaCredentialsSessionCache credCache) {
        this.credCache = credCache;
    }
}
