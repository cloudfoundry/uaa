package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.zone.IdentityZone.getUaaZoneId;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class JdbcIdentityProviderProvisioningTests {

    private JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;
    private RandomValueStringGenerator generator;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private String origin;
    private String uaaZoneId;
    private String otherZoneId1;
    private String otherZoneId2;

    @BeforeEach
    void createDatasource() {
        generator = new RandomValueStringGenerator();
        jdbcIdentityProviderProvisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        origin = "origin-" + generator.generate();
        uaaZoneId = getUaaZoneId();
        otherZoneId1 = "otherZoneId1-" + generator.generate();
        otherZoneId2 = "otherZoneId2-" + generator.generate();
    }

    @Test
    void deleteProvidersInZone() {
        //action - delete zone
        //should delete providers
        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        when(mockIdentityZone.getId()).thenReturn(otherZoneId1);
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        assertNotNull(createdIdp);
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{otherZoneId1}, Integer.class), is(1));
        jdbcIdentityProviderProvisioning.onApplicationEvent(new EntityDeletedEvent<>(mockIdentityZone, null, otherZoneId1));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{otherZoneId1}, Integer.class), is(0));
    }

    @Test
    void deleteProvidersInUaaZone() {
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);
        assertNotNull(createdIdp);
        int count = jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{uaaZoneId}, Integer.class);
        jdbcIdentityProviderProvisioning.onApplicationEvent(new EntityDeletedEvent<>(createdIdp, null, uaaZoneId));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{uaaZoneId}, Integer.class), is(count - 1));
    }

    @Test
    void cannotDeleteUaaProviders() {
        //action try to delete uaa provider
        //should not do anything
        int count = jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{getUaaZoneId()}, Integer.class);
        IdentityProvider uaa = jdbcIdentityProviderProvisioning.retrieveByOrigin(UAA, getUaaZoneId());
        jdbcIdentityProviderProvisioning.onApplicationEvent(new EntityDeletedEvent<>(uaa, null, getUaaZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_provider where identity_zone_id=?", new Object[]{getUaaZoneId()}, Integer.class), is(count));
    }

    @Test
    void createAndUpdateIdentityProviderInDefaultZone() {
        IdentityProvider<UaaIdentityProviderDefinition> idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        String providerDescription = "Test Description";
        idp.setConfig(new UaaIdentityProviderDefinition(null, null));
        idp.getConfig().setProviderDescription(providerDescription);
        idp.setType(UAA);
        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);
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
        assertEquals(uaaZoneId, rawCreatedIdp.get("identity_zone_id").toString().trim());

        idp.setId(createdIdp.getId());
        idp.setLastModified(new Timestamp(System.currentTimeMillis()));
        idp.setName("updated name");
        idp.setCreated(createdIdp.getCreated());
        idp.setConfig(new UaaIdentityProviderDefinition());
        idp.setOriginKey("new origin key");
        idp.setType(UAA);
        idp.setIdentityZoneId("somerandomID");
        createdIdp = jdbcIdentityProviderProvisioning.update(idp, uaaZoneId);

        assertEquals(idp.getName(), createdIdp.getName());
        assertEquals(rawCreatedIdp.get("origin_key"), createdIdp.getOriginKey());
        assertEquals(UAA, createdIdp.getType()); //we don't allow other types anymore
        assertEquals(idp.getConfig(), createdIdp.getConfig());
        assertTrue(Math.abs(idp.getLastModified().getTime() - createdIdp.getLastModified().getTime()) < 1001);
        assertEquals(Integer.valueOf(rawCreatedIdp.get("version").toString()) + 1, createdIdp.getVersion());
        assertEquals(uaaZoneId, createdIdp.getIdentityZoneId());
    }

    @Test
    void createIdentityProviderInOtherZone() {
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);

        IdentityProvider createdIdp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        Map<String, Object> rawCreatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?", createdIdp.getId());

        assertEquals(idp.getName(), createdIdp.getName());
        assertEquals(idp.getOriginKey(), createdIdp.getOriginKey());
        assertEquals(idp.getType(), createdIdp.getType());
        assertEquals(idp.getConfig(), createdIdp.getConfig());

        assertEquals(idp.getName(), rawCreatedIdp.get("name"));
        assertEquals(idp.getOriginKey(), rawCreatedIdp.get("origin_key"));
        assertEquals(idp.getType(), rawCreatedIdp.get("type"));
        assertEquals(idp.getConfig(), JsonUtils.readValue((String) rawCreatedIdp.get("config"), AbstractIdentityProviderDefinition.class));
        assertEquals(otherZoneId1, rawCreatedIdp.get("identity_zone_id"));
    }

    @Test
    void createIdentityProviderWithNonUniqueOriginKeyInDefaultZone() {
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);
        assertThrows(IdpAlreadyExistsException.class, () -> jdbcIdentityProviderProvisioning.create(idp, uaaZoneId));
    }

    @Test
    void createIdentityProviderWithNonUniqueOriginKeyInOtherZone() {
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        assertThrows(IdpAlreadyExistsException.class, () -> jdbcIdentityProviderProvisioning.create(idp, otherZoneId1));
    }

    @Test
    void createIdentityProvidersWithSameOriginKeyInBothZones() {
        IdentityProvider uaaIdp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        jdbcIdentityProviderProvisioning.create(uaaIdp, uaaZoneId);

        String otherZoneId = "otherZoneId-" + generator.generate();
        IdentityProvider otherIdp = MultitenancyFixture.identityProvider(origin, otherZoneId);
        jdbcIdentityProviderProvisioning.create(otherIdp, otherZoneId);
    }

    @Test
    void updateIdentityProviderInDefaultZone() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        idp.setId(idpId);
        idp.setType(OriginKeys.LDAP);
        idp = jdbcIdentityProviderProvisioning.create(idp, uaaZoneId);

        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        idp.setConfig(definition);
        IdentityProvider updatedIdp = jdbcIdentityProviderProvisioning.update(idp, uaaZoneId);

        Map<String, Object> rawUpdatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?", updatedIdp.getId());

        assertEquals(definition, updatedIdp.getConfig());
        assertEquals(definition, JsonUtils.readValue((String) rawUpdatedIdp.get("config"), LdapIdentityProviderDefinition.class));
        assertEquals(getUaaZoneId(), rawUpdatedIdp.get("identity_zone_id"));
    }

    @Test
    void updateIdentityProviderInOtherZone() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        idp.setId(idpId);
        idp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);

        AbstractIdentityProviderDefinition definition = new AbstractIdentityProviderDefinition();
        idp.setConfig(definition);
        IdentityProvider updatedIdp = jdbcIdentityProviderProvisioning.update(idp, otherZoneId1);

        Map<String, Object> rawUpdatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?", updatedIdp.getId());

        assertEquals(definition, updatedIdp.getConfig());
        assertEquals(definition, JsonUtils.readValue((String) rawUpdatedIdp.get("config"), AbstractIdentityProviderDefinition.class));
        assertEquals(otherZoneId1, rawUpdatedIdp.get("identity_zone_id"));
    }

    @Test
    void retrieveIdentityProviderById() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        idp.setId(idpId);
        idp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        IdentityProvider retrievedIdp = jdbcIdentityProviderProvisioning.retrieve(idp.getId(), otherZoneId1);
        assertEquals(idp.getId(), retrievedIdp.getId());
        assertEquals(idp.getConfig(), retrievedIdp.getConfig());
        assertEquals(idp.getName(), retrievedIdp.getName());
        assertEquals(idp.getOriginKey(), retrievedIdp.getOriginKey());
    }

    @Test
    void retrieveAll() {
        List<IdentityProvider> identityProviders = jdbcIdentityProviderProvisioning.retrieveActive(uaaZoneId);
        int numberOfIdps = identityProviders.size();

        IdentityProvider defaultZoneIdp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        jdbcIdentityProviderProvisioning.create(defaultZoneIdp, uaaZoneId);
        identityProviders = jdbcIdentityProviderProvisioning.retrieveActive(uaaZoneId);
        assertEquals(numberOfIdps + 1, identityProviders.size());

        String otherOrigin = "otherOrigin-" + generator.generate();
        String otherZoneId = "otherZoneId-" + generator.generate();
        IdentityProvider otherZoneIdp = MultitenancyFixture.identityProvider(otherOrigin, otherZoneId);
        jdbcIdentityProviderProvisioning.create(otherZoneIdp, otherZoneId);

        identityProviders = jdbcIdentityProviderProvisioning.retrieveActive(otherZoneId);
        assertEquals(1, identityProviders.size());
    }

    @Test
    void retrieveIdentityProviderByOriginInSameZone() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        idp.setId(idpId);
        idp = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);

        IdentityProvider retrievedIdp = jdbcIdentityProviderProvisioning.retrieveByOrigin(idp.getOriginKey(), otherZoneId1);
        assertEquals(idp.getId(), retrievedIdp.getId());
        assertEquals(idp.getConfig(), retrievedIdp.getConfig());
        assertEquals(idp.getName(), retrievedIdp.getName());
        assertEquals(idp.getOriginKey(), retrievedIdp.getOriginKey());
    }

    @Test
    void retrieveIdentityProviderByOriginInDifferentZone() {
        String idpId = "idpId-" + generator.generate();
        IdentityProvider idp = MultitenancyFixture.identityProvider(origin, otherZoneId1);
        idp.setId(idpId);
        IdentityProvider idp1 = jdbcIdentityProviderProvisioning.create(idp, otherZoneId1);
        assertThrows(EmptyResultDataAccessException.class, () -> jdbcIdentityProviderProvisioning.retrieveByOrigin(idp1.getOriginKey(), otherZoneId2));
    }
}
