package org.cloudfoundry.identity.uaa.mfa_provider;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;



public class MfaProviderEndpointsTest {
    @Rule
    public ExpectedException expectedException = ExpectedException.none();
    MfaProviderEndpoints endpoint = new MfaProviderEndpoints();

    @Test
    public void testDefaultIssuer() {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleProvider();
        ResponseEntity<MfaProvider> mfaProviderResponseEntity = endpoint.createMfaProvider(mfaProvider);
        assertEquals(IdentityZoneHolder.get().getName(), mfaProviderResponseEntity.getBody().getConfig().getIssuer());
    }

    private MfaProvider<GoogleMfaProviderConfig> constructGoogleProvider() {
        return new MfaProvider()
                .setName(new RandomValueStringGenerator(5).generate())
                .setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR)
                .setConfig(constructGoogleProviderConfiguration());
    }

    private GoogleMfaProviderConfig constructGoogleProviderConfiguration() {
        return new GoogleMfaProviderConfig().setAlgorithm(GoogleMfaProviderConfig.Algorithm.SHA256);
    }
}