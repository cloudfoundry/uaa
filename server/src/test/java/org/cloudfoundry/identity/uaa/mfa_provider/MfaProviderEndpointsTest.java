package org.cloudfoundry.identity.uaa.mfa_provider;

import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.Mockito;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;


public class MfaProviderEndpointsTest {

    MfaProviderEndpoints endpoint = new MfaProviderEndpoints();
    MfaProviderProvisioning provisioning;
    MfaProviderValidator validator;

    @Before
    public void setup() {

        provisioning = mock(JdbcMfaProviderProvisioning.class);
        validator = mock(GeneralMfaProviderValidator.class);
        endpoint.setMfaProviderProvisioning(provisioning);
        endpoint.setMfaProviderValidator(validator);
    }

    @Test
    public void testDefaultIssuer() {
        MfaProvider<GoogleMfaProviderConfig> mfaProvider = constructGoogleProvider();
        Mockito.when(provisioning.create(Mockito.any(), Mockito.anyString())).thenReturn(mfaProvider);


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