package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

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
class JdbcSamlServiceProviderProvisioningTest {

    private JdbcSamlServiceProviderProvisioning db;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private Authentication authentication = mock(Authentication.class);

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
        IdentityZoneHolder.clear();
    }

    @Test
    void retrieveActive() {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        assertEquals(0, db.retrieveActive(IdentityZoneHolder.get().getId()).size());
        String zoneId = IdentityZone.getUaaZoneId();
        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        SamlServiceProvider createdSp = db.create(sp, sp.getIdentityZoneId());
        assertEquals(1, db.retrieveActive(IdentityZoneHolder.get().getId()).size());
        jdbcTemplate.update("update service_provider set active=?", false);
        assertEquals(0, db.retrieveActive(IdentityZoneHolder.get().getId()).size());
    }

    @Test
    void createAndUpdateSamlServiceProviderInDefaultZone() {
        IdentityZoneHolder.set(IdentityZone.getUaa());
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
        createdSp = db.update(sp, IdentityZoneHolder.get().getId());

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
        IdentityZoneHolder.set(zone);

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
        IdentityZoneHolder.set(zone);

        SamlServiceProvider sp = createSamlServiceProvider(zone.getId());
        db.create(sp, sp.getIdentityZoneId());

        // The current zone is not where we are creating the zone.
        IdentityZoneHolder.set(IdentityZone.getUaa());
        assertThrows(EmptyResultDataAccessException.class, () -> db.retrieve(sp.getId(), IdentityZoneHolder.get().getId()));
    }

    @Test
    void updateSamlServiceProviderInWrongZone() {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(zone);

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
        IdentityZoneHolder.set(IdentityZone.getUaa());
        assertThrows(EmptyResultDataAccessException.class, () -> db.update(sp, IdentityZoneHolder.get().getId()));
    }

    @Test
    void createSamlServiceProviderWithSameEntityIdInDefaultZone() {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        String zoneId = IdentityZone.getUaaZoneId();
        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        db.create(sp, sp.getIdentityZoneId());
        assertThrows(SamlSpAlreadyExistsException.class, () -> db.create(sp, sp.getIdentityZoneId()));
    }

    @Test
    void createSamlServiceProviderWithSameEntityIdInOtherZone() {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(zone);
        SamlServiceProvider sp = createSamlServiceProvider(zone.getId());
        db.create(sp, sp.getIdentityZoneId());
        assertThrows(SamlSpAlreadyExistsException.class, () -> db.create(sp, sp.getIdentityZoneId()));
    }

    @Test
    void createSamlServiceProviderWithSameEntityIdInDifferentZones() {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        String zoneId = IdentityZone.getUaaZoneId();
        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        db.create(sp, sp.getIdentityZoneId());

        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(zone);
        zoneId = zone.getId();
        sp.setIdentityZoneId(zoneId);
        db.create(sp, sp.getIdentityZoneId());
    }

    @Test
    void deleteSamlServiceProvidersInUaaZone() {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        String zoneId = IdentityZone.getUaaZoneId();

        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        SamlServiceProvider createdSp = db.create(sp, sp.getIdentityZoneId());

        assertNotNull(createdSp);
        assertThat(jdbcTemplate.queryForObject("select count(*) from service_provider where identity_zone_id=?",
                new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(1));
        db.onApplicationEvent(new EntityDeletedEvent<>(createdSp, authentication, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from service_provider where identity_zone_id=?",
                new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(0));
    }

    @Test
    void deleteSamlServiceProvidersInOtherZone() {
        String zoneId = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId, zoneId);
        IdentityZoneHolder.set(zone);

        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        SamlServiceProvider createdSp = db.create(sp, sp.getIdentityZoneId());

        assertNotNull(createdSp);
        assertThat(jdbcTemplate.queryForObject("select count(*) from service_provider where identity_zone_id=?",
                new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(1));
        db.onApplicationEvent(new EntityDeletedEvent<>(createdSp, authentication, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?",
                new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(0));
    }
}
