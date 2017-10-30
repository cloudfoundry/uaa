package org.cloudfoundry.identity.uaa.mfa_provider;

import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import com.warrenstrange.googleauth.IGoogleAuthenticator;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;

public class GoogleAuthenticatorAdapter {
    public String getOtpAuthURL(IGoogleAuthenticator authenticator, UaaPrincipal uaaPrincipal) {
        return GoogleAuthenticatorQRGenerator.getOtpAuthURL("UAA", uaaPrincipal.getName(), authenticator.createCredentials(uaaPrincipal.getId()));
    }
}
