package org.cloudfoundry.identity.uaa.mfa_provider;

import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.PreparedStatement;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

public class JdbcMfaProviderProvisioningTest extends JdbcTestBase {
    JdbcMfaProviderProvisioning mfaProviderProvisioning;

    @Before
    public void setup() {
        mfaProviderProvisioning = new JdbcMfaProviderProvisioning(jdbcTemplate);
    }

    @Test
    public void testCreateAndRetrieve() {
        MfaProvider mfaProvider = constructGoogleProvider();
        String zoneId = IdentityZoneHolder.get().getId();
        assertEquals(0, (int) jdbcTemplate.queryForObject("select count(*) from mfa_providers where identity_zone_id=? and name=?", new Object[]{zoneId, mfaProvider.getName()}, Integer.class));

        MfaProvider created = mfaProviderProvisioning.create(mfaProvider, zoneId);
        assertNotNull(created);
        assertEquals(1, (int) jdbcTemplate.queryForObject("select count(*) from mfa_providers where identity_zone_id=? and id=?", new Object[]{zoneId, created.getId()}, Integer.class));

        MfaProvider retrieved = mfaProviderProvisioning.retrieve(created.getId(), zoneId);
        assertEquals(mfaProvider.getName(), retrieved.getName());
        assertEquals(mfaProvider.getConfig(), retrieved.getConfig());
    }

    @Test
    public void testRetrieve() {
        MfaProvider mfaProvider = constructGoogleProvider();
        mfaProvider.setActive(false);
        String zoneId = IdentityZoneHolder.get().getId();
        MfaProvider created = mfaProviderProvisioning.create(mfaProvider, zoneId);
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