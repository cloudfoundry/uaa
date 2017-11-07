package org.cloudfoundry.identity.uaa.mfa;


import com.warrenstrange.googleauth.ICredentialRepository;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigDoesNotExistException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpSession;
import java.util.List;

public class UserGoogleMfaCredentialsProvisioning implements ICredentialRepository {

    private static final String SESSION_CREDENTIAL_ATTR_NAME = "SESSION_USER_GOOGLE_MFA_CREDENTIALS";
    private MfaProviderProvisioning mfaProviderProvisioning;

    UserMfaCredentialsProvisioning<UserGoogleMfaCredentials> jdbcProvisioner;

    @Override
    public String getSecretKey(String userId) {
        HttpSession session = session();
        UserGoogleMfaCredentials creds = (UserGoogleMfaCredentials)session.getAttribute(SESSION_CREDENTIAL_ATTR_NAME);
        if(creds == null) {
            creds = jdbcProvisioner.retrieve(userId);
        }
        return creds.getSecretKey();
    }

    @Override
    public void saveUserCredentials(String userName, String secretKey, int validationCode, List<Integer> scratchCodes) {

        HttpSession session = session();

        UserGoogleMfaCredentials creds = new UserGoogleMfaCredentials(userName, secretKey, validationCode, scratchCodes);
        MfaProvider mfaProvider = mfaProviderProvisioning.retrieveByName(IdentityZoneHolder.get().getConfig().getMfaConfig().getProviderName(), IdentityZoneHolder.get().getId());
        creds.setMfaProviderId(mfaProvider.getId());
        session.setAttribute(SESSION_CREDENTIAL_ATTR_NAME, creds);
    }

    public boolean activeUserCredentialExists(String userId) {
        UserGoogleMfaCredentials retrieved;
        try {
            retrieved = jdbcProvisioner.retrieve(userId);
        } catch (UserMfaConfigDoesNotExistException e) {
            return false;
        }
        return (retrieved != null);
    }

    public void persistCredentials() {
        HttpSession session = session();
        UserGoogleMfaCredentials creds = (UserGoogleMfaCredentials) session.getAttribute(SESSION_CREDENTIAL_ATTR_NAME);
        if(creds == null) {
            return;
        }
        MfaProvider mfaProvider = mfaProviderProvisioning.retrieveByName(IdentityZoneHolder.get().getConfig().getMfaConfig().getProviderName(), IdentityZoneHolder.get().getId());
        creds.setMfaProviderId(mfaProvider.getId());
        jdbcProvisioner.save(creds);
        session.removeAttribute(SESSION_CREDENTIAL_ATTR_NAME);
    }

    public boolean isFirstTimeMFAUser(UaaPrincipal uaaPrincipal) {
        if(uaaPrincipal == null) throw new RuntimeException("User information is not present in session.");
        return session().getAttribute(SESSION_CREDENTIAL_ATTR_NAME) != null;
    }

    public UserMfaCredentialsProvisioning<UserGoogleMfaCredentials> getJdbcProvisioner() {
        return jdbcProvisioner;
    }

    public void setJdbcProvisioner(UserMfaCredentialsProvisioning<UserGoogleMfaCredentials> jdbcProvisioner) {
        this.jdbcProvisioner = jdbcProvisioner;
    }

    private HttpSession session() {
        HttpSession session = ((ServletRequestAttributes) RequestContextHolder.getRequestAttributes()).getRequest().getSession(false);
        if(session == null) {
            throw new RuntimeException("Session not found");
        }
        return session;
    }

    public void setMfaProviderProvisioning(MfaProviderProvisioning mfaProviderProvisioning) {
        this.mfaProviderProvisioning = mfaProviderProvisioning;
    }
}
