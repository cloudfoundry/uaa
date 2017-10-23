package org.cloudfoundry.identity.uaa.mfa_provider;

public interface UserMfaCredentialsProvisioning<T extends UserGoogleMfaCredentials> {
    void save(T credentials);
    void update(T credentials);
    T retrieve(String userId);
    int delete(String userId);
    void activateUser(String userId);
}
