package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.mfa.exception.MfaAlreadyExistsException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;

import java.util.List;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;

@WithDatabaseContext
class JdbcMfaProviderProvisioningTest {

    private JdbcMfaProviderProvisioning mfaProviderProvisioning;
    private MfaProviderValidator mfaProviderValidator;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void setUp() {
        mfaProviderValidator = mock(GeneralMfaProviderValidator.class);
        mfaProviderProvisioning = new JdbcMfaProviderProvisioning(jdbcTemplate, mfaProviderValidator);
    }

    @Test
    void createAndRetrieve() {
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
    void createDuplicate() {
        MfaProvider mfaProvider = constructGoogleProvider();
        String zoneId = IdentityZoneHolder.get().getId();
        assertEquals(0, (int) jdbcTemplate.queryForObject("select count(*) from mfa_providers where identity_zone_id=? and name=?", new Object[]{zoneId, mfaProvider.getName()}, Integer.class));
        doNothing().when(mfaProviderValidator);
        mfaProviderProvisioning.create(mfaProvider, zoneId);
        assertThrowsWithMessageThat(MfaAlreadyExistsException.class,
                () -> mfaProviderProvisioning.create(mfaProvider, zoneId),
                is("An MFA Provider with that name already exists."));
    }

    @Test
    void createDuplicateWorksAcrossZones() {
        MfaProvider mfaProvider = constructGoogleProvider();
        String zoneId = IdentityZoneHolder.get().getId();
        assertEquals(0, (int) jdbcTemplate.queryForObject("select count(*) from mfa_providers where identity_zone_id=? and name=?", new Object[]{zoneId, mfaProvider.getName()}, Integer.class));
        doNothing().when(mfaProviderValidator);
        mfaProviderProvisioning.create(mfaProvider, zoneId);
        mfaProviderProvisioning.create(mfaProvider, zoneId + "-other-zone");
    }

    @Test
    void updateDuplicate() {
        MfaProvider firstProvider = mfaProviderProvisioning.create(constructGoogleProvider(), IdentityZoneHolder.get().getId());
        MfaProvider secondProvider = mfaProviderProvisioning.create(constructGoogleProvider(), IdentityZoneHolder.get().getId());

        secondProvider.setName(firstProvider.getName());

        assertThrowsWithMessageThat(MfaAlreadyExistsException.class,
                () -> mfaProviderProvisioning.update(secondProvider, IdentityZoneHolder.get().getId()),
                is("An MFA Provider with that name already exists."));
    }

    @Test
    void createAndUpdate() {
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
    void retrieveAll() {
        String zoneId = IdentityZoneHolder.get().getId();
        List<MfaProvider> providers = mfaProviderProvisioning.retrieveAll(zoneId);
        doNothing().when(mfaProviderValidator);
        int beforeCount = providers.size();

        MfaProvider mfaProvider = constructGoogleProvider();
        mfaProviderProvisioning.create(mfaProvider, zoneId);

        providers = mfaProviderProvisioning.retrieveAll(zoneId);
        int afterCount = providers.size();
        assertEquals(1, afterCount - beforeCount);
    }

    @Test
    void retrieve() {
        MfaProvider mfaProvider = constructGoogleProvider();
        doNothing().when(mfaProviderValidator);
        String zoneId = IdentityZoneHolder.get().getId();
        MfaProvider created = mfaProviderProvisioning.create(mfaProvider, zoneId);
        assertEquals(mfaProvider.getName(), created.getName());
        assertNotNull(created.getId());
    }

    @Test
    void retrieveByName() {
        MfaProvider createdProvider = mfaProviderProvisioning.create(constructGoogleProvider(), IdentityZoneHolder.get().getId());
        assertEquals(
                createdProvider.getId(),
                mfaProviderProvisioning.retrieveByName(createdProvider.getName(), createdProvider.getIdentityZoneId()).getId()
        );
    }

    @Test
    void delete() {
        String zoneId = IdentityZoneHolder.get().getId();
        doNothing().when(mfaProviderValidator);
        MfaProvider mfaProvider = mfaProviderProvisioning.create(constructGoogleProvider(), zoneId);
        assertNotNull(mfaProviderProvisioning.retrieve(mfaProvider.getId(), zoneId));

        mfaProviderProvisioning.deleteByMfaProvider(mfaProvider.getId(), zoneId);

        assertThrows(EmptyResultDataAccessException.class,
                () -> mfaProviderProvisioning.retrieve(mfaProvider.getId(), zoneId));
    }

    @Test
    void deleteByIdentityZone() {
        String zoneId = IdentityZoneHolder.get().getId();
        doNothing().when(mfaProviderValidator);
        MfaProvider mfaProvider = mfaProviderProvisioning.create(constructGoogleProvider(), zoneId);
        assertNotNull(mfaProviderProvisioning.retrieve(mfaProvider.getId(), zoneId));

        mfaProviderProvisioning.deleteByIdentityZone(zoneId);

        assertThrows(EmptyResultDataAccessException.class,
                () -> mfaProviderProvisioning.retrieve(mfaProvider.getId(), zoneId));
    }

    private static MfaProvider<GoogleMfaProviderConfig> constructGoogleProvider() {
        return new MfaProvider<GoogleMfaProviderConfig>()
                .setName(new RandomValueStringGenerator(10).generate())
                .setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR)
                .setIdentityZoneId(IdentityZoneHolder.get().getId())
                .setConfig(new GoogleMfaProviderConfig());
    }

}