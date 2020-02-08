package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import java.util.List;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class JdbcIdentityZoneProvisioningTests extends JdbcTestBase {

    private JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning;
    private RandomValueStringGenerator randomValueStringGenerator;

    @Before
    public void createDatasource() {
        jdbcIdentityZoneProvisioning = new JdbcIdentityZoneProvisioning(jdbcTemplate);
        randomValueStringGenerator = new RandomValueStringGenerator(8);
    }

    @Test
    public void test_delete_zone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[]{createdIdZone.getId()}, Integer.class), is(1));
        jdbcIdentityZoneProvisioning.onApplicationEvent(new EntityDeletedEvent<>(identityZone, null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[]{createdIdZone.getId()}, Integer.class), is(0));
    }

    @Test
    public void test_cannot_delete_uaa_zone() {
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[]{IdentityZone.getUaaZoneId()}, Integer.class), is(1));
        jdbcIdentityZoneProvisioning.onApplicationEvent(new EntityDeletedEvent<>(IdentityZone.getUaa(), null, IdentityZoneHolder.getCurrentZoneId()));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[]{IdentityZone.getUaaZoneId()}, Integer.class), is(1));
    }

    @Test
    public void testCreateIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertEquals(3600, createdIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(7200, createdIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertTrue(createdIdZone.isActive());
    }

    @Test
    public void testCreateIdentityZone_Subdomain_Becomes_LowerCase() {
        String subdomain = randomValueStringGenerator.generate().toUpperCase();
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), subdomain);
        identityZone.setId(randomValueStringGenerator.generate());

        identityZone.setSubdomain(subdomain);
        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(subdomain.toLowerCase(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void test_null_subdomain() {
        jdbcIdentityZoneProvisioning.retrieveBySubdomain(null);
    }

    @Test
    public void testUpdateIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());

        String newDomain = new RandomValueStringGenerator().generate();
        createdIdZone.setSubdomain(newDomain);
        createdIdZone.setDescription("new desc");
        createdIdZone.setName("new name");
        IdentityZone updatedIdZone = jdbcIdentityZoneProvisioning.update(createdIdZone);

        assertEquals(createdIdZone.getId(), updatedIdZone.getId());
        assertEquals(createdIdZone.getSubdomain().toLowerCase(), updatedIdZone.getSubdomain());
        assertEquals(createdIdZone.getName(), updatedIdZone.getName());
        assertEquals(createdIdZone.getDescription(), updatedIdZone.getDescription());
        assertEquals(createdIdZone.isActive(), updatedIdZone.isActive());
    }

    @Test
    public void testUpdateIdentityZone_SubDomain_Is_LowerCase() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());

        String newDomain = new RandomValueStringGenerator().generate();
        createdIdZone.setSubdomain(newDomain.toUpperCase());
        createdIdZone.setDescription("new desc");
        createdIdZone.setName("new name");
        IdentityZone updatedIdZone = jdbcIdentityZoneProvisioning.update(createdIdZone);

        assertEquals(createdIdZone.getId(), updatedIdZone.getId());
        assertEquals(createdIdZone.getSubdomain().toLowerCase(), updatedIdZone.getSubdomain());
        assertEquals(createdIdZone.getName(), updatedIdZone.getName());
        assertEquals(createdIdZone.getDescription(), updatedIdZone.getDescription());
    }

    @Test
    public void testCreateIdentityZoneInactive() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertFalse(createdIdZone.isActive());
    }

    @Test
    public void testUpdateIdentityZoneSetInactive() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        assertTrue(createdIdZone.isActive());

        createdIdZone.setActive(false);
        IdentityZone updatedIdZone = jdbcIdentityZoneProvisioning.update(createdIdZone);

        assertFalse(updatedIdZone.isActive());
    }

    @Test
    public void testDeleteInactiveIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);
        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        int deletedZones = jdbcIdentityZoneProvisioning.deleteByIdentityZone(createdIdZone.getId());

        assertEquals(1, deletedZones);
    }

    @Test(expected = ZoneDoesNotExistsException.class)
    public void testUpdateNonExistentIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.update(identityZone);
    }

    @Test
    public void testCreateDuplicateIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone("there-can-be-only-one", "there-can-be-only-one");
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);
        try {
            jdbcIdentityZoneProvisioning.create(identityZone);
            fail("Should have thrown exception");
        } catch (ZoneAlreadyExistsException e) {
            // success
        }
    }

    @Test
    public void testCreateDuplicateIdentityZoneSubdomain() {
        IdentityZone identityZone = MultitenancyFixture.identityZone("there-can-be-only-one", "there-can-be-only-one");
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);
        try {
            identityZone.setId(new RandomValueStringGenerator().generate());
            jdbcIdentityZoneProvisioning.create(identityZone);
            fail("Should have thrown exception");
        } catch (ZoneAlreadyExistsException e) {
            // success
        }
    }

    @Test
    public void testGetIdentityZone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieve(identityZone.getId());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());
        assertEquals(identityZone.getSubdomain(), retrievedIdZone.getSubdomain());
        assertEquals(identityZone.getName(), retrievedIdZone.getName());
        assertEquals(identityZone.getDescription(), retrievedIdZone.getDescription());
        assertEquals(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertTrue(retrievedIdZone.isActive());
    }

    @Test
    public void testGetAllIdentityZones() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);

        List<IdentityZone> identityZones = jdbcIdentityZoneProvisioning.retrieveAll();

        assertEquals(2, identityZones.size());
        assertTrue(identityZones.contains(identityZone));
    }

    @Test
    public void testGetIdentityZoneBySubdomain() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieveBySubdomain(identityZone.getSubdomain());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());
        assertEquals(identityZone.getSubdomain(), retrievedIdZone.getSubdomain());
        assertEquals(identityZone.getName(), retrievedIdZone.getName());
        assertEquals(identityZone.getDescription(), retrievedIdZone.getDescription());
        assertEquals(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertTrue(retrievedIdZone.isActive());
    }

    @Test
    public void testGetInactiveIdentityZoneFails() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        try {
            jdbcIdentityZoneProvisioning.retrieve(createdIdZone.getId());
            fail("Able to retrieve inactive zone.");
        } catch (ZoneDoesNotExistsException e) {
            assertThat(e.getMessage(), containsString(createdIdZone.getId()));
        }
    }

    @Test
    public void testGetInactiveIdentityZoneIgnoringActiveFlag() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(randomValueStringGenerator.generate(), randomValueStringGenerator.generate());
        identityZone.setId(randomValueStringGenerator.generate());
        identityZone.setActive(false);

        IdentityZone createdIdZone = jdbcIdentityZoneProvisioning.create(identityZone);

        IdentityZone retrievedIdZone = jdbcIdentityZoneProvisioning.retrieveIgnoreActiveFlag(createdIdZone.getId());

        assertEquals(identityZone.getId(), retrievedIdZone.getId());
        assertEquals(identityZone.getSubdomain(), retrievedIdZone.getSubdomain());
        assertEquals(identityZone.getName(), retrievedIdZone.getName());
        assertEquals(identityZone.getDescription(), retrievedIdZone.getDescription());
        assertEquals(identityZone.getConfig().getTokenPolicy().getAccessTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(identityZone.getConfig().getTokenPolicy().getRefreshTokenValidity(), retrievedIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
        assertFalse(retrievedIdZone.isActive());
    }

    @Test
    public void testRetrieveAllZonesIncludesInactive() {

    }

    @Test
    public void test() {
    }
}
