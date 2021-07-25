package org.cloudfoundry.identity.uaa.mfa;


import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigDoesNotExistException;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import com.google.zxing.WriterException;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.ICredentialRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

public class UserGoogleMfaCredentialsProvisioning implements ICredentialRepository {
    private static Logger logger = LoggerFactory.getLogger(UserGoogleMfaCredentialsProvisioning.class);
    private MfaProviderProvisioning mfaProviderProvisioning;
    private GoogleAuthenticator authenticator;
    private UserMfaCredentialsProvisioning<UserGoogleMfaCredentials> jdbcProvisioner;

    public void setAuthenticator(GoogleAuthenticator authenticator) {
        this.authenticator = authenticator;
    }

    public UserGoogleMfaCredentials getUserGoogleMfaCredentials(String userId) {
        MfaProvider provider = mfaProviderProvisioning.retrieveByName(
            IdentityZoneHolder.get().getConfig().getMfaConfig().getProviderName(),
            IdentityZoneHolder.get().getId());
        return getUserGoogleMfaCredentials(userId, provider.getId());
    }

    public UserGoogleMfaCredentials getUserGoogleMfaCredentials(String userId, String providerId) {
        try {
            return jdbcProvisioner.retrieve(userId, providerId);
        } catch (UserMfaConfigDoesNotExistException e) {
            logger.debug("Unable to find MFA config for user:"+userId);
        }
        return null;

    }

    @Override
    public String getSecretKey(String userId) {
        throw new UnsupportedOperationException();
    }

    public String getOtpAuthURL(String qrIssuer, UserGoogleMfaCredentials credentials, String userName) throws IOException, WriterException {
        return MfaRegisterQRGenerator.getQRCodePngDataUri(qrIssuer, userName, credentials.getSecretKey());
    }

    public UserGoogleMfaCredentials createUserCredentials(String userId) {
        GoogleAuthenticatorKey credentials = authenticator.createCredentials(userId);
        return new UserGoogleMfaCredentials(userId,
                                                                      credentials.getKey(),
                                                                      credentials.getVerificationCode(),
                                                                      credentials.getScratchCodes());
    }

    public boolean isValidCode(UserGoogleMfaCredentials credentials, Integer code) {
        return authenticator.authorize(credentials.getSecretKey(), code);
    }

    @Override
    public void saveUserCredentials(String userId, String secretKey, int validationCode, List<Integer> scratchCodes) {
        //no op
    }

    public void saveUserCredentials(UserGoogleMfaCredentials credentials) {
        IdentityZone zone = IdentityZoneHolder.get();
        jdbcProvisioner.save(credentials, zone.getId());
    }

    public boolean activeUserCredentialExists(String userId, String providerId) {
        return getUserGoogleMfaCredentials(userId, providerId)!=null;
    }


    public boolean isFirstTimeMFAUser(UaaPrincipal uaaPrincipal) {
        if (uaaPrincipal == null) throw new RuntimeException("User information is not present in session.");
        return getUserGoogleMfaCredentials(uaaPrincipal.getId()) == null;
    }

    public void setJdbcProvisioner(UserMfaCredentialsProvisioning<UserGoogleMfaCredentials> jdbcProvisioner) {
        this.jdbcProvisioner = jdbcProvisioner;
    }

    public void setMfaProviderProvisioning(MfaProviderProvisioning mfaProviderProvisioning) {
        this.mfaProviderProvisioning = mfaProviderProvisioning;
    }

}
