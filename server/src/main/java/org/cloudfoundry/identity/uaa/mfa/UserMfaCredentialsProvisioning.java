package org.cloudfoundry.identity.uaa.mfa;

public interface UserMfaCredentialsProvisioning<T extends UserGoogleMfaCredentials> {
    void save(T credentials, String zoneId);
    void update(T credentials, String zoneId);
    T retrieve(String userId, String mfaProviderId);
    int delete(String userId);
}
