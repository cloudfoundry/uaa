package org.cloudfoundry.identity.uaa.mfa;


import com.warrenstrange.googleauth.ICredentialRepository;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigDoesNotExistException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import java.util.List;

public class UserGoogleMfaCredentialsProvisioning implements ICredentialRepository {

    private MfaProviderProvisioning mfaProviderProvisioning;
    private MfaCredentialsSessionCache credCache;

    UserMfaCredentialsProvisioning<UserGoogleMfaCredentials> jdbcProvisioner;

    @Override
    public String getSecretKey(String userId) {
        UserGoogleMfaCredentials creds = credCache.getCredentials();
        if(creds == null) {
            MfaProvider provider = mfaProviderProvisioning.retrieveByName(
                    IdentityZoneHolder.get().getConfig().getMfaConfig().getProviderName(),
                    IdentityZoneHolder.get().getId());
            creds = jdbcProvisioner.retrieve(userId, provider.getId());
        }
        return creds.getSecretKey();
    }

    @Override
    public void saveUserCredentials(String userName, String secretKey, int validationCode, List<Integer> scratchCodes) {
        UserGoogleMfaCredentials creds = new UserGoogleMfaCredentials(userName, secretKey, validationCode, scratchCodes);
        MfaProvider mfaProvider = mfaProviderProvisioning.retrieveByName(IdentityZoneHolder.get().getConfig().getMfaConfig().getProviderName(), IdentityZoneHolder.get().getId());
        creds.setMfaProviderId(mfaProvider.getId());
        credCache.putCredentials(creds);
    }

    public boolean activeUserCredentialExists(String userId, String mfaProviderId) {
        UserGoogleMfaCredentials retrieved;
        try {
            retrieved = jdbcProvisioner.retrieve(userId, mfaProviderId);
        } catch (UserMfaConfigDoesNotExistException e) {
            return false;
        }
        return (retrieved != null);
    }

    public void persistCredentials() {
        String zoneId = IdentityZoneHolder.get().getId();
        UserGoogleMfaCredentials creds = credCache.getCredentials();
        if(creds == null) {
            return;
        }
        MfaProvider mfaProvider = mfaProviderProvisioning.retrieveByName(IdentityZoneHolder.get().getConfig().getMfaConfig().getProviderName(), zoneId);
        creds.setMfaProviderId(mfaProvider.getId());
        jdbcProvisioner.save(creds, zoneId);
        credCache.removeCredentials();
    }

    public boolean isFirstTimeMFAUser(UaaPrincipal uaaPrincipal) {
        if(uaaPrincipal == null) throw new RuntimeException("User information is not present in session.");
        return credCache.getCredentials() != null;
    }

    public void setJdbcProvisioner(UserMfaCredentialsProvisioning<UserGoogleMfaCredentials> jdbcProvisioner) {
        this.jdbcProvisioner = jdbcProvisioner;
    }

    public void setMfaProviderProvisioning(MfaProviderProvisioning mfaProviderProvisioning) {
        this.mfaProviderProvisioning = mfaProviderProvisioning;
    }

    public void setCredCache(MfaCredentialsSessionCache credCache) {
        this.credCache = credCache;
    }
}
