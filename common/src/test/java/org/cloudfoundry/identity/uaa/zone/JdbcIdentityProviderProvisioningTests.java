package org.cloudfoundry.identity.uaa.zone;

import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.EmptyResultDataAccessException;

import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

public class JdbcIdentityProviderProvisioningTests extends JdbcTestBase {

    private JdbcIdentityProviderProvisioning db;

    @Before
    public void createDatasource() throws Exception {
        IdentityZoneHolder.clear();
        db = new JdbcIdentityProviderProvisioning(jdbcTemplate);
    }

    @After
    public void cleanUp() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void testCreateAndUpdateIdentityProviderInDefaultZone() throws Exception {
        String zoneId = IdentityZone.getUaa().getId();
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zoneId);

        IdentityProvider createdIdp = db.create(idp);
        Map<String, Object> rawCreatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?",createdIdp.getId());

        assertEquals(idp.getName(), createdIdp.getName());
        assertEquals(idp.getOriginKey(), createdIdp.getOriginKey());
        assertEquals(idp.getType(), createdIdp.getType());
        assertEquals(idp.getConfig(), createdIdp.getConfig());

        assertEquals(idp.getName(), rawCreatedIdp.get("name"));
        assertEquals(idp.getOriginKey(), rawCreatedIdp.get("origin_key"));
        assertEquals(idp.getType(), rawCreatedIdp.get("type"));
        assertEquals(idp.getConfig(), JsonUtils.readValue((String)rawCreatedIdp.get("config"), AbstractIdentityProviderDefinition.class));
        assertEquals(zoneId, rawCreatedIdp.get("identity_zone_id").toString().trim());

        idp.setId(createdIdp.getId());
        idp.setLastModified(new Timestamp(System.currentTimeMillis()));
        idp.setName("updated name");
        idp.setCreated(createdIdp.getCreated());
        idp.setConfig(new AbstractIdentityProviderDefinition());
        idp.setOriginKey("new origin key");
        idp.setType("new type");
        idp.setIdentityZoneId("somerandomID");
        createdIdp = db.update(idp);

        assertEquals(idp.getName(), createdIdp.getName());
        assertEquals(rawCreatedIdp.get("origin_key"), createdIdp.getOriginKey());
        assertEquals(Origin.UNKNOWN, createdIdp.getType()); //we don't allow other types anymore
        assertEquals(idp.getConfig(), createdIdp.getConfig());
        assertEquals(idp.getLastModified().getTime()/1000, createdIdp.getLastModified().getTime()/1000);
        assertEquals(Integer.valueOf(rawCreatedIdp.get("version").toString())+1, createdIdp.getVersion());
        assertEquals(zoneId, createdIdp.getIdentityZoneId());
    }

    @Test
    public void testCreateIdentityProviderInOtherZone() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");

        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zone.getId());

        IdentityProvider createdIdp = db.create(idp);
        Map<String, Object> rawCreatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?",createdIdp.getId());

        assertEquals(idp.getName(), createdIdp.getName());
        assertEquals(idp.getOriginKey(), createdIdp.getOriginKey());
        assertEquals(idp.getType(), createdIdp.getType());
        assertEquals(idp.getConfig(), createdIdp.getConfig());

        assertEquals(idp.getName(), rawCreatedIdp.get("name"));
        assertEquals(idp.getOriginKey(), rawCreatedIdp.get("origin_key"));
        assertEquals(idp.getType(), rawCreatedIdp.get("type"));
        assertEquals(idp.getConfig(), JsonUtils.readValue((String)rawCreatedIdp.get("config"), AbstractIdentityProviderDefinition.class));
        assertEquals(zone.getId(), rawCreatedIdp.get("identity_zone_id"));
    }

    @Test(expected=IdpAlreadyExistsException.class)
    public void testCreateIdentityProviderWithNonUniqueOriginKeyInDefaultZone() throws Exception {
        String zoneId = IdentityZone.getUaa().getId();
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zoneId);
        db.create(idp);
        db.create(idp);
    }

    @Test(expected=IdpAlreadyExistsException.class)
    public void testCreateIdentityProviderWithNonUniqueOriginKeyInOtherZone() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zone.getId());
        db.create(idp);
        db.create(idp);
    }

    @Test
    public void testCreateIdentityProvidersWithSameOriginKeyInBothZones() throws Exception {
        String zoneId = IdentityZone.getUaa().getId();
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zoneId);
        db.create(idp);
        idp.setIdentityZoneId(MultitenancyFixture.identityZone(UUID.randomUUID().toString(),"myzone").getId());
        db.create(idp);
    }

    @Test
    public void testUpdateIdentityProviderInDefaultZone() throws Exception {
        String zoneId = IdentityZone.getUaa().getId();
        String originKey = RandomStringUtils.randomAlphabetic(6);
        String idpId = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zoneId);
        idp.setId(idpId);
        idp.setType(Origin.LDAP);
        idp = db.create(idp);

        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        idp.setConfig(definition);
        IdentityProvider updatedIdp = db.update(idp);

        Map<String, Object> rawUpdatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?",updatedIdp.getId());

        assertEquals(definition, updatedIdp.getConfig());
        assertEquals(definition, JsonUtils.readValue((String)rawUpdatedIdp.get("config"),LdapIdentityProviderDefinition.class));
        assertEquals(IdentityZone.getUaa().getId(), rawUpdatedIdp.get("identity_zone_id"));
    }

    @Test
    public void testUpdateIdentityProviderInOtherZone() throws Exception {
        IdentityZone zone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(),"myzone");
        String originKey = RandomStringUtils.randomAlphabetic(6);
        String idpId = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, zone.getId());
        idp.setId(idpId);
        idp = db.create(idp);

        AbstractIdentityProviderDefinition definition = new AbstractIdentityProviderDefinition();
        idp.setConfig(definition);
        IdentityProvider updatedIdp = db.update(idp);

        Map<String, Object> rawUpdatedIdp = jdbcTemplate.queryForMap("select * from identity_provider where id = ?",updatedIdp.getId());

        assertEquals(definition, updatedIdp.getConfig());
        assertEquals(definition, JsonUtils.readValue((String)rawUpdatedIdp.get("config"), AbstractIdentityProviderDefinition.class));
        assertEquals(zone.getId(), rawUpdatedIdp.get("identity_zone_id"));
    }

    @Test
    public void testRetrieveIdentityProviderById() {
        String uaaZoneId = IdentityZone.getUaa().getId();
        String originKey = RandomStringUtils.randomAlphabetic(6);
        String identityZoneId = RandomStringUtils.randomAlphabetic(6);
        String idpId = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, uaaZoneId);
        idp.setId(idpId);
        IdentityZone zone = MultitenancyFixture.identityZone(identityZoneId, identityZoneId);
        idp.setIdentityZoneId(zone.getId());
        idp = db.create(idp);
        IdentityProvider retrievedIdp = db.retrieve(idp.getId());
        assertEquals(idp.getId(), retrievedIdp.getId());
        assertEquals(idp.getConfig(), retrievedIdp.getConfig());
        assertEquals(idp.getName(), retrievedIdp.getName());
        assertEquals(idp.getOriginKey(), retrievedIdp.getOriginKey());
    }

    @Test
    public void testRetrieveAll() throws Exception {
        String uaaZoneId = IdentityZone.getUaa().getId();
        List<IdentityProvider> identityProviders = db.retrieveActive(uaaZoneId);
        int numberOfIdps =  identityProviders.size();
        String origin = RandomStringUtils.randomAlphabetic(6);

        IdentityProvider defaultZoneIdp = MultitenancyFixture.identityProvider(origin, uaaZoneId);
        db.create(defaultZoneIdp);
        identityProviders = db.retrieveActive(uaaZoneId);
        assertEquals(numberOfIdps + 1, identityProviders.size());

        IdentityZone otherZone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(), "myzone");
        String originKey = RandomStringUtils.randomAlphabetic(6);
        IdentityProvider otherZoneIdp = MultitenancyFixture.identityProvider(originKey, otherZone.getId());
        db.create(otherZoneIdp);

        identityProviders = db.retrieveActive(otherZone.getId());
        assertEquals(1, identityProviders.size());
    }

    @Test
    public void testRetrieveIdentityProviderByOriginInSameZone() {
        String originKey = RandomStringUtils.randomAlphabetic(6);
        String identityZoneId = RandomStringUtils.randomAlphabetic(6);
        String idpId = RandomStringUtils.randomAlphabetic(6);
        IdentityZone identityZone = MultitenancyFixture.identityZone(identityZoneId, "myzone");

        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey, identityZone.getId());
        idp.setId(idpId);
        idp = db.create(idp);

        IdentityProvider retrievedIdp = db.retrieveByOrigin(idp.getOriginKey(), identityZone.getId());
        assertEquals(idp.getId(), retrievedIdp.getId());
        assertEquals(idp.getConfig(), retrievedIdp.getConfig());
        assertEquals(idp.getName(), retrievedIdp.getName());
        assertEquals(idp.getOriginKey(), retrievedIdp.getOriginKey());
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void testRetrieveIdentityProviderByOriginInDifferentZone() {
        String originKey = RandomStringUtils.randomAlphabetic(6);
        String identityZoneId1 = RandomStringUtils.randomAlphabetic(6);
        String identityZoneId2 = RandomStringUtils.randomAlphabetic(6);
        String idpId = RandomStringUtils.randomAlphabetic(6);
        IdentityZone identityZone1 = MultitenancyFixture.identityZone(identityZoneId1, "myzone1");
        IdentityZone identityZone2 = MultitenancyFixture.identityZone(identityZoneId2, "myzone2");
        IdentityProvider idp = MultitenancyFixture.identityProvider(originKey,identityZone1.getId());
        idp.setId(idpId);
        idp.setIdentityZoneId(identityZone1.getId());
        IdentityProvider idp1 = db.create(idp);
        db.retrieveByOrigin(idp1.getOriginKey(), identityZone2.getId());
    }
}
