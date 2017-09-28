package org.cloudfoundry.identity.uaa.mfa_provider;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;

public class JdbcMfaProviderProvisioningTest extends JdbcTestBase {
    JdbcMfaProviderProvisioning mfaProviderProvisioning;
    private MfaProviderValidator mfaProviderValidator;

    @Before
    public void setup() {
        mfaProviderValidator = mock(GeneralMfaProviderValidator.class);
        mfaProviderProvisioning = new JdbcMfaProviderProvisioning(jdbcTemplate, mfaProviderValidator);
    }

    @Test
    public void testCreateAndRetrieve() {
        MfaProvider mfaProvider = constructGoogleProvider();
        String zoneId = IdentityZoneHolder.get().getId();
        assertEquals(0, (int) jdbcTemplate.queryForObject("select count(*) from mfa_providers where identity_zone_id=? and name=?", new Object[]{zoneId, mfaProvider.getName()}, Integer.class));
        doNothing().when(mfaProviderValidator);

        MfaProvider created = mfaProviderProvisioning.create(mfaProvider, zoneId);
        assertNotNull(created);
        assertEquals(1, (int) jdbcTemplate.queryForObject("select count(*) from mfa_providers where identity_zone_id=? and id=?", new Object[]{zoneId, created.getId()}, Integer.class));

        MfaProvider retrieved = mfaProviderProvisioning.retrieve(created.getId(), zoneId);
        assertEquals(mfaProvider.getName(), retrieved.getName());
        assertEquals(mfaProvider.getConfig(), retrieved.getConfig());
    }

    @Test
    public void testRetrieveAll() {
        String zoneId = IdentityZoneHolder.get().getId();
        List<MfaProvider> providers = mfaProviderProvisioning.retrieveAll(zoneId);
        doNothing().when(mfaProviderValidator);
        int beforeCount = providers.size();

        MfaProvider mfaProvider = constructGoogleProvider();
        mfaProviderProvisioning.create(mfaProvider, zoneId);

        providers = mfaProviderProvisioning.retrieveAll(zoneId);
        int afterCount = providers.size();
        assertEquals(1, afterCount-beforeCount);
    }


    @Test
    public void testRetrieve() {
        MfaProvider mfaProvider = constructGoogleProvider();
        mfaProvider.setActive(false);
        doNothing().when(mfaProviderValidator);
        String zoneId = IdentityZoneHolder.get().getId();
        MfaProvider created = mfaProviderProvisioning.create(mfaProvider, zoneId);
        assertEquals(mfaProvider.getName(), created.getName());
        assertNotNull(created.getId());
    }

    private MfaProvider<GoogleMfaProviderConfig> constructGoogleProvider() {
        return new MfaProvider<GoogleMfaProviderConfig>()
                .setName(new RandomValueStringGenerator(10).generate())
                .setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR)
                .setIdentityZoneId(IdentityZoneHolder.get().getId())
                .setConfig(constructGoogleProviderConfiguration());
    }

    private GoogleMfaProviderConfig constructGoogleProviderConfiguration() {
        return new GoogleMfaProviderConfig().setAlgorithm(GoogleMfaProviderConfig.Algorithm.SHA256);
    }
}