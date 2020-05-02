package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.test.RandomStringGetter;
import org.cloudfoundry.identity.uaa.test.RandomStringGetterExtension;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;

import java.sql.Timestamp;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

@WithDatabaseContext
@ExtendWith(RandomStringGetterExtension.class)
class JdbcSamlServiceProviderProvisioningTest {

    private JdbcSamlServiceProviderProvisioning db;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void createDatasource() {
        db = new JdbcSamlServiceProviderProvisioning(jdbcTemplate);
        cleanUp();
    }

    @AfterEach
    void cleanUp() {
        jdbcTemplate.update("delete from service_provider");
    }

    @Test
    void retrieveActive() {
        assertEquals(0, db.retrieveActive(IdentityZone.getUaaZoneId()).size());
        String zoneId = IdentityZone.getUaaZoneId();
        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        SamlServiceProvider createdSp = db.create(sp, sp.getIdentityZoneId());
        assertEquals(1, db.retrieveActive(IdentityZone.getUaaZoneId()).size());
        jdbcTemplate.update("update service_provider set active=?", false);
        assertEquals(0, db.retrieveActive(IdentityZone.getUaaZoneId()).size());
    }

    @Test
    void createAndUpdateSamlServiceProviderInDefaultZone() {
        String zoneId = IdentityZone.getUaaZoneId();

        SamlServiceProvider sp = createSamlServiceProvider(zoneId);

        SamlServiceProvider createdSp = db.create(sp, sp.getIdentityZoneId());
        Map<String, Object> rawCreatedSp = jdbcTemplate.queryForMap("select * from service_provider where id = ?",
                createdSp.getId());

        assertEquals(sp.getName(), createdSp.getName());
        assertEquals(sp.getConfig(), createdSp.getConfig());

        assertEquals(sp.getName(), rawCreatedSp.get("name"));
        assertEquals(sp.getConfig(),
                JsonUtils.readValue((String) rawCreatedSp.get("config"), SamlServiceProviderDefinition.class));
        assertEquals(zoneId, rawCreatedSp.get("identity_zone_id").toString().trim());

        sp.setId(createdSp.getId());
        sp.setLastModified(new Timestamp(System.currentTimeMillis()));
        sp.setName("updated name");
        sp.setCreated(createdSp.getCreated());
        SamlServiceProviderDefinition updatedConfig = new SamlServiceProviderDefinition();
        updatedConfig.setMetaDataLocation(SamlTestUtils.UNSIGNED_SAML_SP_METADATA);
        sp.setConfig(updatedConfig);
        sp.setIdentityZoneId(zoneId);
        createdSp = db.update(sp, IdentityZone.getUaaZoneId());

        assertEquals(sp.getName(), createdSp.getName());
        assertEquals(sp.getConfig(), createdSp.getConfig());
        assertTrue(Math.abs(sp.getLastModified().getTime() - createdSp.getLastModified().getTime()) < 1001);
        assertEquals(Integer.valueOf(rawCreatedSp.get("version").toString()) + 1, createdSp.getVersion());
        assertEquals(zoneId, createdSp.getIdentityZoneId());
    }

    private SamlServiceProvider createSamlServiceProvider(String zoneId) {
        SamlServiceProvider sp = new SamlServiceProvider();
        sp.setActive(true);
        SamlServiceProviderDefinition config = new SamlServiceProviderDefinition();
        config.setMetaDataLocation(SamlTestUtils.SAML_SP_METADATA);
        sp.setConfig(config);
        sp.setEntityId(SamlTestUtils.SP_ENTITY_ID);
        sp.setIdentityZoneId(zoneId);
        sp.setLastModified(new Date());
        sp.setName("Unit Test SAML SP");
        return sp;
    }

    @Test
    void createSamlServiceProviderInOtherZone() {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");

        SamlServiceProvider sp = createSamlServiceProvider(zone.getId());

        SamlServiceProvider createdSp = db.create(sp, sp.getIdentityZoneId());
        Map<String, Object> rawCreatedSp = jdbcTemplate.queryForMap("select * from service_provider where id = ?",
                createdSp.getId());

        assertEquals(sp.getName(), createdSp.getName());
        assertEquals(sp.getConfig(), createdSp.getConfig());

        assertEquals(sp.getName(), rawCreatedSp.get("name"));
        assertEquals(sp.getConfig(),
                JsonUtils.readValue((String) rawCreatedSp.get("config"), SamlServiceProviderDefinition.class));
        assertEquals(zone.getId(), rawCreatedSp.get("identity_zone_id"));
    }

    @Test
    void getSamlServiceProviderForWrongZone() {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");

        SamlServiceProvider sp = createSamlServiceProvider(zone.getId());
        db.create(sp, sp.getIdentityZoneId());

        // The current zone is not where we are creating the zone.
        assertThrows(EmptyResultDataAccessException.class, () -> db.retrieve(sp.getId(), IdentityZone.getUaaZoneId()));
    }

    @Test
    void updateSamlServiceProviderInWrongZone() {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");

        SamlServiceProvider sp = createSamlServiceProvider(zone.getId());

        SamlServiceProvider createdSp = db.create(sp, sp.getIdentityZoneId());
        Map<String, Object> rawCreatedSp = jdbcTemplate.queryForMap("select * from service_provider where id = ?",
                createdSp.getId());

        assertEquals(sp.getName(), createdSp.getName());
        assertEquals(sp.getConfig(), createdSp.getConfig());

        assertEquals(sp.getName(), rawCreatedSp.get("name"));
        assertEquals(sp.getConfig(),
                JsonUtils.readValue((String) rawCreatedSp.get("config"), SamlServiceProviderDefinition.class));
        assertEquals(zone.getId(), rawCreatedSp.get("identity_zone_id").toString().trim());

        sp.setId(createdSp.getId());
        sp.setLastModified(new Timestamp(System.currentTimeMillis()));
        sp.setName("updated name");
        sp.setCreated(createdSp.getCreated());
        SamlServiceProviderDefinition updatedConfig = new SamlServiceProviderDefinition();
        updatedConfig.setMetaDataLocation(SamlTestUtils.UNSIGNED_SAML_SP_METADATA);
        sp.setConfig(updatedConfig);
        sp.setIdentityZoneId(zone.getId());
        // Switch to a different zone before updating.
        assertThrows(EmptyResultDataAccessException.class, () -> db.update(sp, IdentityZone.getUaaZoneId()));
    }

    @Test
    void createSamlServiceProviderWithSameEntityIdInDefaultZone() {
        String zoneId = IdentityZone.getUaaZoneId();
        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        db.create(sp, sp.getIdentityZoneId());
        assertThrows(SamlSpAlreadyExistsException.class, () -> db.create(sp, sp.getIdentityZoneId()));
    }

    @Test
    void createSamlServiceProviderWithSameEntityIdInOtherZone() {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        SamlServiceProvider sp = createSamlServiceProvider(zone.getId());
        db.create(sp, sp.getIdentityZoneId());
        assertThrows(SamlSpAlreadyExistsException.class, () -> db.create(sp, sp.getIdentityZoneId()));
    }

    @Test
    void createSamlServiceProviderWithSameEntityIdInDifferentZones() {
        String zoneId = IdentityZone.getUaaZoneId();
        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        db.create(sp, sp.getIdentityZoneId());

        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        zoneId = zone.getId();
        sp.setIdentityZoneId(zoneId);
        db.create(sp, sp.getIdentityZoneId());
    }

    @Test
    void deleteSamlServiceProvidersInUaaZone() {
        String zoneId = IdentityZone.getUaaZoneId();

        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        SamlServiceProvider createdSp = db.create(sp, sp.getIdentityZoneId());

        assertNotNull(createdSp);
        assertThat(jdbcTemplate.queryForObject("select count(*) from service_provider where identity_zone_id=?",
                new Object[]{IdentityZone.getUaaZoneId()}, Integer.class), is(1));
        db.onApplicationEvent(new EntityDeletedEvent<>(createdSp, mock(Authentication.class), zoneId));
        assertThat(jdbcTemplate.queryForObject("select count(*) from service_provider where identity_zone_id=?",
                new Object[]{zoneId}, Integer.class), is(0));
    }

    @Test
    void deleteSamlServiceProvidersInOtherZone(RandomStringGetter zoneId) {
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId.get(), zoneId.get());

        SamlServiceProvider sp = createSamlServiceProvider(zoneId.get());
        SamlServiceProvider createdSp = db.create(sp, sp.getIdentityZoneId());

        assertNotNull(createdSp);
        assertThat(jdbcTemplate.queryForObject("select count(*) from service_provider where identity_zone_id=?",
                new Object[]{zone.getId()}, Integer.class), is(1));
        db.onApplicationEvent(new EntityDeletedEvent<>(createdSp, mock(Authentication.class), zone.getId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?",
                new Object[]{zone.getId()}, Integer.class), is(0));
    }
}
