package org.cloudfoundry.identity.uaa.provider.saml.idp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;

import java.sql.Timestamp;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

public class JdbcSamlServiceProviderProvisioningTest extends JdbcTestBase {

    private JdbcSamlServiceProviderProvisioning db;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private Authentication authentication = mock(Authentication.class);

    @Before
    public void createDatasource() throws Exception {
        db = new JdbcSamlServiceProviderProvisioning(jdbcTemplate);
    }

    @After
    public void cleanUp() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void testCreateAndUpdateSamlServiceProviderInDefaultZone() throws Exception {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        String zoneId = IdentityZone.getUaa().getId();

        SamlServiceProvider sp = createSamlServiceProvider(zoneId);

        SamlServiceProvider createdSp = db.create(sp);
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
        createdSp = db.update(sp);

        assertEquals(sp.getName(), createdSp.getName());
        assertEquals(sp.getConfig(), createdSp.getConfig());
        assertEquals(sp.getLastModified().getTime() / 1000, createdSp.getLastModified().getTime() / 1000);
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
    public void testCreateSamlServiceProviderInOtherZone() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(zone);

        SamlServiceProvider sp = createSamlServiceProvider(zone.getId());

        SamlServiceProvider createdSp = db.create(sp);
        Map<String, Object> rawCreatedSp = jdbcTemplate.queryForMap("select * from service_provider where id = ?",
                createdSp.getId());

        assertEquals(sp.getName(), createdSp.getName());
        assertEquals(sp.getConfig(), createdSp.getConfig());

        assertEquals(sp.getName(), rawCreatedSp.get("name"));
        assertEquals(sp.getConfig(),
                JsonUtils.readValue((String) rawCreatedSp.get("config"), SamlServiceProviderDefinition.class));
        assertEquals(zone.getId(), rawCreatedSp.get("identity_zone_id"));
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void testGetSamlServiceProviderForWrongZone() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(zone);

        SamlServiceProvider sp = createSamlServiceProvider(zone.getId());
        db.create(sp);

        // The current zone is not where we are creating the zone.
        IdentityZoneHolder.set(IdentityZone.getUaa());
        db.retrieve(sp.getId());
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void testUpdateSamlServiceProviderInWrongZone() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(zone);

        SamlServiceProvider sp = createSamlServiceProvider(zone.getId());

        SamlServiceProvider createdSp = db.create(sp);
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
        db.update(sp);
    }

    @Test(expected = SamlSpAlreadyExistsException.class)
    public void testCreateSamlServiceProviderWithSameEntityIdInDefaultZone() throws Exception {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        String zoneId = IdentityZone.getUaa().getId();
        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        db.create(sp);
        db.create(sp);
    }

    @Test(expected = SamlSpAlreadyExistsException.class)
    public void testCreateSamlServiceProviderWithSameEntityIdInOtherZone() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(zone);
        SamlServiceProvider sp = createSamlServiceProvider(zone.getId());
        db.create(sp);
        db.create(sp);
    }

    @Test
    public void testCreateSamlServiceProviderWithSameEntityIdInDifferentZones() throws Exception {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        String zoneId = IdentityZone.getUaa().getId();
        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        db.create(sp);
 
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(zone);
        zoneId = zone.getId();
        sp.setIdentityZoneId(zoneId);
        db.create(sp);
    }

    @Test
    public void testDeleteSamlServiceProvidersInUaaZone() {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        String zoneId = IdentityZone.getUaa().getId();

        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        SamlServiceProvider createdSp = db.create(sp);

        assertNotNull(createdSp);
        assertThat(jdbcTemplate.queryForObject("select count(*) from service_provider where identity_zone_id=?",
                new Object[] { IdentityZoneHolder.get().getId() }, Integer.class), is(1));
        db.onApplicationEvent(new EntityDeletedEvent<>(createdSp, authentication));
        assertThat(jdbcTemplate.queryForObject("select count(*) from service_provider where identity_zone_id=?",
                new Object[] { IdentityZoneHolder.get().getId() }, Integer.class), is(0));
    }

    @Test
    public void testDeleteSamlServiceProvidersInOtherZone() {
        String zoneId = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId, zoneId);
        IdentityZoneHolder.set(zone);

        SamlServiceProvider sp = createSamlServiceProvider(zoneId);
        SamlServiceProvider createdSp = db.create(sp);

        assertNotNull(createdSp);
        assertThat(jdbcTemplate.queryForObject("select count(*) from service_provider where identity_zone_id=?",
                new Object[] { IdentityZoneHolder.get().getId() }, Integer.class), is(1));
        db.onApplicationEvent(new EntityDeletedEvent<>(createdSp, authentication));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?",
                new Object[] { IdentityZoneHolder.get().getId() }, Integer.class), is(0));
    }
}
