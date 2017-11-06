package org.cloudfoundry.identity.uaa.mfa;

public interface UserMfaCredentialsProvisioning<T extends UserGoogleMfaCredentials> {
    void save(T credentials);
    void update(T credentials);
    T retrieve(String userId);
    int delete(String userId);
}
