package org.cloudfoundry.identity.uaa.zone;

import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.*;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.*;

@WithDatabaseContext
class JdbcIdentityProviderProvisioningTests {

    private JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;
    private RandomValueStringGenerator generator;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @BeforeEach
    void createDatasource() {
        generator = new RandomValueStringGenerator();
        IdentityZoneHolder.clear();
        jdbcIdentityProviderProvisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
    }

    @AfterEach
    void clearZone() {
        IdentityZoneHolder.clear();
    }

    @Test
    void deleteProvidersInZone() {
        //action - delete zone
        //should delete providers
        String zoneId = generator.generate();
        IdentityZone zone = MultitenancyFixture.identityZone(zoneId, zoneId);
        IdentityZoneHolder.set(zone);
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zoneId);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, zoneId);
        assertNotNull(createdIdp);
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(1));
        jdbcIdentityProviderProvisioning.onApplicationEvent(new EntityDeletedEvent<>(IdentityZoneHolder.get(), null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(0));
    }

    @Test
    void deleteProvidersInUaaZone() {
        String zoneId = IdentityZone.getUaaZoneId();
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zoneId);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, zoneId);
        assertNotNull(createdIdp);
        int count = jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class);
        jdbcIdentityProviderProvisioning.onApplicationEvent(new EntityDeletedEvent<>(createdIdp, null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(count - 1));
    }

    @Test
    void cannotDeleteUaaProviders() {
        //action try to delete uaa provider
        //should not do anything
        int count = jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class);
        IdentityProvider uaa = jdbcIdentityProviderProvisioning.retrieveByOrigin(UAA, IdentityZoneHolder.get().getId());
        jdbcIdentityProviderProvisioning.onApplicationEvent(new EntityDeletedEvent<>(uaa, null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{IdentityZoneHolder.get().getId()}, Integer.class), is(count));
    }

    @Test
    void createAndUpdateIdentityProviderInDefaultZone() {
        String zoneId = IdentityZone.getUaaZoneId();
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider<UaaIdentityProviderDefinition> idp = MultitenancyFixture.identityProvider(originKey, zoneId);
        String providerDescription = "Test Description";
        idp.setConfig(new UaaIdentityProviderDefinition(null, null));
        idp.getConfig().setProviderDescription(providerDescription);
        idp.setType(UAA);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, zoneId);
        Map<String, Object> rawCreatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?", createdIdp.getId());

        assertEquals(idp.getName(), createdIdp.getName());
        assertEquals(idp.getOriginKey(), createdIdp.getOriginKey());
        assertEquals(idp.getType(), createdIdp.getType());
        assertEquals(idp.getConfig(), createdIdp.getConfig());
        assertEquals(providerDescription, createdIdp.getConfig().getProviderDescription());

        assertEquals(idp.getName(), rawCreatedIdp.get("name"));
        assertEquals(idp.getOriginKey(), rawCreatedIdp.get("origin_key"));
        assertEquals(idp.getType(), rawCreatedIdp.get("type"));
        assertEquals(idp.getConfig(), JsonUtils.readValue((String) rawCreatedIdp.get("config"), UaaIdentityProviderDefinition.class));
        assertEquals(zoneId, rawCreatedIdp.get("identity_zone_id").toString().trim());

        idp.setId(createdIdp.getId());
        idp.setLastModified(new Timestamp(System.currentTimeMillis()));
        idp.setName("updated name");
        idp.setCreated(createdIdp.getCreated());
        idp.setConfig(new UaaIdentityProviderDefinition());
        idp.setOriginKey("new origin key");
        idp.setType(UAA);
        idp.setIdentityZoneId("somerandomID");
        createdIdp = jdbcIdentityProviderProvisioning.update(idp, zoneId);

        assertEquals(idp.getName(), createdIdp.getName());
        assertEquals(rawCreatedIdp.get("origin_key"), createdIdp.getOriginKey());
        assertEquals(UAA, createdIdp.getType()); //we don't allow other types anymore
        assertEquals(idp.getConfig(), createdIdp.getConfig());
        assertTrue(Math.abs(idp.getLastModified().getTime() - createdIdp.getLastModified().getTime()) < 1001);
        assertEquals(Integer.valueOf(rawCreatedIdp.get("version").toString()) + 1, createdIdp.getVersion());
        assertEquals(zoneId, createdIdp.getIdentityZoneId());
    }

    @Test
    void createIdentityProviderInOtherZone() {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(zone);
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zone.getId());

        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, zone.getId());
        Map<String, Object> rawCreatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?", createdIdp.getId());

        assertEquals(idp.getName(), createdIdp.getName());
        assertEquals(idp.getOriginKey(), createdIdp.getOriginKey());
        assertEquals(idp.getType(), createdIdp.getType());
        assertEquals(idp.getConfig(), createdIdp.getConfig());

        assertEquals(idp.getName(), rawCreatedIdp.get("name"));
        assertEquals(idp.getOriginKey(), rawCreatedIdp.get("origin_key"));
        assertEquals(idp.getType(), rawCreatedIdp.get("type"));
        assertEquals(idp.getConfig(), JsonUtils.readValue((String) rawCreatedIdp.get("config"), AbstractIdentityProviderDefinition.class));
        assertEquals(zone.getId(), rawCreatedIdp.get("identity_zone_id"));
    }

    @Test
    void createIdentityProviderWithNonUniqueOriginKeyInDefaultZone() {
        String zoneId = IdentityZone.getUaaZoneId();
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zoneId);
        jdbcIdentityProviderProvisioning.create(idp, zoneId);
        assertThrows(IdpAlreadyExistsException.class, () -> jdbcIdentityProviderProvisioning.create(idp, zoneId));
    }

    @Test
    void createIdentityProviderWithNonUniqueOriginKeyInOtherZone() {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(zone);
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zone.getId());
        jdbcIdentityProviderProvisioning.create(idp, zone.getId());
        assertThrows(IdpAlreadyExistsException.class, () -> jdbcIdentityProviderProvisioning.create(idp, zone.getId()));
    }

    @Test
    void createIdentityProvidersWithSameOriginKeyInBothZones() {
        String zoneId = IdentityZone.getUaaZoneId();
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zoneId);
        jdbcIdentityProviderProvisioning.create(idp, zoneId);
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(zone);
        idp.setIdentityZoneId(zone.getId());
        jdbcIdentityProviderProvisioning.create(idp, zone.getId());
    }

    @Test
    void updateIdentityProviderInDefaultZone() {
        String zoneId = IdentityZone.getUaaZoneId();
        String originKey = RandomStringUtils.randomAlphabetic(6);
        String idpId = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zoneId);
        idp.setId(idpId);
        idp.setType(OriginKeys.LDAP);
        idp = jdbcIdentityProviderProvisioning.create(idp, zoneId);

        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        idp.setConfig(definition);
        IdentityProvider updatedIdp = jdbcIdentityProviderProvisioning.update(idp, zoneId);

        Map<String, Object> rawUpdatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?", updatedIdp.getId());

        assertEquals(definition, updatedIdp.getConfig());
        assertEquals(definition, JsonUtils.readValue((String) rawUpdatedIdp.get("config"), LdapIdentityProviderDefinition.class));
        assertEquals(IdentityZone.getUaaZoneId(), rawUpdatedIdp.get("identity_zone_id"));
    }

    @Test
    void updateIdentityProviderInOtherZone() {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(zone);
        String originKey = RandomStringUtils.randomAlphabetic(6);
        String idpId = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zone.getId());
        idp.setId(idpId);
        idp = jdbcIdentityProviderProvisioning.create(idp, zone.getId());

        AbstractIdentityProviderDefinition definition = new AbstractIdentityProviderDefinition();
        idp.setConfig(definition);
        IdentityProvider updatedIdp = jdbcIdentityProviderProvisioning.update(idp, zone.getId());

        Map<String, Object> rawUpdatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?", updatedIdp.getId());

        assertEquals(definition, updatedIdp.getConfig());
        assertEquals(definition, JsonUtils.readValue((String) rawUpdatedIdp.get("config"), AbstractIdentityProviderDefinition.class));
        assertEquals(zone.getId(), rawUpdatedIdp.get("identity_zone_id"));
    }

    @Test
    void retrieveIdentityProviderById() {
        String uaaZoneId = IdentityZone.getUaaZoneId();
        String originKey = RandomStringUtils.randomAlphabetic(6);
        String identityZoneId = RandomStringUtils.randomAlphabetic(6);
        String idpId = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, uaaZoneId);
        idp.setId(idpId);
        IdentityZone zone = MultitenancyFixture.identityZone(identityZoneId, identityZoneId);
        IdentityZoneHolder.set(zone);
        idp.setIdentityZoneId(zone.getId());
        idp = jdbcIdentityProviderProvisioning.create(idp, zone.getId());
        IdentityProvider retrievedIdp = jdbcIdentityProviderProvisioning.retrieve(idp.getId(), zone.getId());
        assertEquals(idp.getId(), retrievedIdp.getId());
        assertEquals(idp.getConfig(), retrievedIdp.getConfig());
        assertEquals(idp.getName(), retrievedIdp.getName());
        assertEquals(idp.getOriginKey(), retrievedIdp.getOriginKey());
    }

    @Test
    void retrieveAll() {
        String uaaZoneId = IdentityZone.getUaaZoneId();
        List<IdentityProvider> identityProviders = jdbcIdentityProviderProvisioning.retrieveActive(uaaZoneId);
        int numberOfIdps = identityProviders.size();
        String origin = RandomStringUtils.randomAlphabetic(6);

        IdentityProvider defaultZoneIdp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        jdbcIdentityProviderProvisioning.create(defaultZoneIdp, uaaZoneId);
        identityProviders = jdbcIdentityProviderProvisioning.retrieveActive(uaaZoneId);
        assertEquals(numberOfIdps + 1, identityProviders.size());

        IdentityZone otherZone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        IdentityZoneHolder.set(otherZone);
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider otherZoneIdp = MultitenancyFixture.identityProvider(originKey, otherZone.getId());
        jdbcIdentityProviderProvisioning.create(otherZoneIdp, otherZone.getId());

        identityProviders = jdbcIdentityProviderProvisioning.retrieveActive(otherZone.getId());
        assertEquals(1, identityProviders.size());
    }

    @Test
    void retrieveIdentityProviderByOriginInSameZone() {
        String originKey = RandomStringUtils.randomAlphabetic(6);
        String identityZoneId = RandomStringUtils.randomAlphabetic(6);
        String idpId = RandomStringUtils.randomAlphabetic(6);
        IdentityZone identityZone = MultitenancyFixture.identityZone(identityZoneId, "myzone");
        IdentityZoneHolder.set(identityZone);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, identityZone.getId());
        idp.setId(idpId);
        idp = jdbcIdentityProviderProvisioning.create(idp, identityZoneId);

        IdentityProvider retrievedIdp = jdbcIdentityProviderProvisioning.retrieveByOrigin(idp.getOriginKey(), identityZone.getId());
        assertEquals(idp.getId(), retrievedIdp.getId());
        assertEquals(idp.getConfig(), retrievedIdp.getConfig());
        assertEquals(idp.getName(), retrievedIdp.getName());
        assertEquals(idp.getOriginKey(), retrievedIdp.getOriginKey());
    }

    @Test
    void retrieveIdentityProviderByOriginInDifferentZone() {
        String originKey = RandomStringUtils.randomAlphabetic(6);
        String identityZoneId1 = RandomStringUtils.randomAlphabetic(6);
        String identityZoneId2 = RandomStringUtils.randomAlphabetic(6);
        String idpId = RandomStringUtils.randomAlphabetic(6);
        IdentityZone identityZone1 = MultitenancyFixture.identityZone(identityZoneId1, "myzone1");
        IdentityZone identityZone2 = MultitenancyFixture.identityZone(identityZoneId2, "myzone2");
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, identityZone1.getId());
        idp.setId(idpId);
        idp.setIdentityZoneId(identityZone1.getId());
        IdentityProvider idp1 = jdbcIdentityProviderProvisioning.create(idp, identityZoneId1);
        assertThrows(EmptyResultDataAccessException.class, () -> jdbcIdentityProviderProvisioning.retrieveByOrigin(idp1.getOriginKey(), identityZone2.getId()));
    }
}
