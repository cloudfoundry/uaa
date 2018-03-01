package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.mfa.exception.MfaAlreadyExistsException;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;

public class JdbcMfaProviderProvisioningTest extends JdbcTestBase {
    JdbcMfaProviderProvisioning mfaProviderProvisioning;
    private MfaProviderValidator mfaProviderValidator;

    @Rule
    public ExpectedException expection = ExpectedException.none();

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
    public void testCreateDuplicate() {
        MfaProvider mfaProvider = constructGoogleProvider();
        String zoneId = IdentityZoneHolder.get().getId();
        assertEquals(0, (int) jdbcTemplate.queryForObject("select count(*) from mfa_providers where identity_zone_id=? and name=?", new Object[]{zoneId, mfaProvider.getName()}, Integer.class));
        doNothing().when(mfaProviderValidator);
        expection.expect(MfaAlreadyExistsException.class);
        expection.expectMessage("An MFA Provider with that name already exists.");
        mfaProviderProvisioning.create(mfaProvider, zoneId);
        mfaProviderProvisioning.create(mfaProvider, zoneId);

    }

    @Test
    public void testCreateDuplicateWorksAcrossZones() {
        MfaProvider mfaProvider = constructGoogleProvider();
        String zoneId = IdentityZoneHolder.get().getId();
        assertEquals(0, (int) jdbcTemplate.queryForObject("select count(*) from mfa_providers where identity_zone_id=? and name=?", new Object[]{zoneId, mfaProvider.getName()}, Integer.class));
        doNothing().when(mfaProviderValidator);
        mfaProviderProvisioning.create(mfaProvider, zoneId);
        mfaProviderProvisioning.create(mfaProvider, zoneId+"-other-zone");

    }
    @Test
    public void testUpdateDuplicate() {
        MfaProvider firstProvider = mfaProviderProvisioning.create(constructGoogleProvider(), IdentityZoneHolder.get().getId());
        MfaProvider secondProvider = mfaProviderProvisioning.create(constructGoogleProvider(), IdentityZoneHolder.get().getId());

        secondProvider.setName(firstProvider.getName());

        expection.expect(MfaAlreadyExistsException.class);
        expection.expectMessage("An MFA Provider with that name already exists.");
        mfaProviderProvisioning.update(secondProvider, IdentityZoneHolder.get().getId());
    }

    @Test
    public void testCreateAndUpdate() {
        MfaProvider mfaProvider = constructGoogleProvider();
        String zoneId = IdentityZoneHolder.get().getId();
        assertEquals(0, (int) jdbcTemplate.queryForObject("select count(*) from mfa_providers where identity_zone_id=? and name=?", new Object[]{zoneId, mfaProvider.getName()}, Integer.class));

        MfaProvider created = mfaProviderProvisioning.create(mfaProvider, zoneId);
        assertNotNull(created);
        assertEquals(1, (int) jdbcTemplate.queryForObject("select count(*) from mfa_providers where identity_zone_id=? and id=?", new Object[]{zoneId, created.getId()}, Integer.class));

        mfaProvider = created;
        mfaProvider.setName(new RandomValueStringGenerator(5).generate());
        mfaProvider.getConfig().setIssuer("new issuer");

        MfaProvider updated = mfaProviderProvisioning.update(created, zoneId);
        assertNotNull(updated);

        MfaProvider retrieved = mfaProviderProvisioning.retrieve(created.getId(), zoneId);
        assertEquals(mfaProvider.getName(), retrieved.getName());
        assertEquals(mfaProvider.getConfig().getIssuer(), retrieved.getConfig().getIssuer());
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
        doNothing().when(mfaProviderValidator);
        String zoneId = IdentityZoneHolder.get().getId();
        MfaProvider created = mfaProviderProvisioning.create(mfaProvider, zoneId);
        assertEquals(mfaProvider.getName(), created.getName());
        assertNotNull(created.getId());
    }
    @Test
    public void testRetrieveByName() {
        MfaProvider createdProvider = mfaProviderProvisioning.create(constructGoogleProvider(), IdentityZoneHolder.get().getId());
        assertEquals(
            createdProvider.getId(),
            mfaProviderProvisioning.retrieveByName(createdProvider.getName(), createdProvider.getIdentityZoneId()).getId()
        );
    }

    @Test
    public void testDelete() {
        String zoneId = IdentityZoneHolder.get().getId();
        doNothing().when(mfaProviderValidator);
        MfaProvider mfaProvider = mfaProviderProvisioning.create(constructGoogleProvider(), zoneId);
        assertNotNull(mfaProviderProvisioning.retrieve(mfaProvider.getId(), zoneId));

        mfaProviderProvisioning.deleteByMfaProvider(mfaProvider.getId(), zoneId);

        expection.expect(EmptyResultDataAccessException.class);
        mfaProviderProvisioning.retrieve(mfaProvider.getId(), zoneId);
    }

    @Test
    public void testDeleteByIdentityZone() {
        String zoneId = IdentityZoneHolder.get().getId();
        doNothing().when(mfaProviderValidator);
        MfaProvider mfaProvider = mfaProviderProvisioning.create(constructGoogleProvider(), zoneId);
        assertNotNull(mfaProviderProvisioning.retrieve(mfaProvider.getId(), zoneId));

        mfaProviderProvisioning.deleteByIdentityZone(zoneId);

        expection.expect(EmptyResultDataAccessException.class);
        mfaProviderProvisioning.retrieve(mfaProvider.getId(), zoneId);
    }

    private MfaProvider<GoogleMfaProviderConfig> constructGoogleProvider() {
        return new MfaProvider<GoogleMfaProviderConfig>()
                .setName(new RandomValueStringGenerator(10).generate())
                .setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR)
                .setIdentityZoneId(IdentityZoneHolder.get().getId())
                .setConfig(constructGoogleProviderConfiguration());
    }

    private GoogleMfaProviderConfig constructGoogleProviderConfiguration() {
        return new GoogleMfaProviderConfig();
    }
}