package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Before;
import org.junit.Test;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class JdbcIdentityZoneProvisioningTests extends JdbcTestBase {

    private JdbcIdentityZoneProvisioning db;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator(8);
    @Before
    public void createDatasource() throws Exception {
        db = new JdbcIdentityZoneProvisioning(jdbcTemplate);
    }

    @Test
    public void test_delete_zone() {
        IdentityZone identityZone = MultitenancyFixture.identityZone(generator.generate(),generator.generate());
        identityZone.setId(generator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));

        IdentityZone createdIdZone = db.create(identityZone);
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[] {createdIdZone.getId()}, Integer.class), is(1));
        db.onApplicationEvent(new EntityDeletedEvent<>(identityZone, null));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[] {createdIdZone.getId()}, Integer.class), is(0));
    }

    @Test
    public void test_cannot_delete_uaa_zone() {
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[] {IdentityZone.getUaa().getId()}, Integer.class), is(1));
        db.onApplicationEvent(new EntityDeletedEvent<>(IdentityZone.getUaa(), null));
        assertThat(jdbcTemplate.queryForObject("select count(*) from identity_zone where id = ?", new Object[] {IdentityZone.getUaa().getId()}, Integer.class), is(1));
    }

    @Test
    public void testCreateIdentityZone() throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone(generator.generate(),generator.generate());
        identityZone.setId(generator.generate());
        identityZone.setConfig(new IdentityZoneConfiguration(new TokenPolicy(3600, 7200)));

        IdentityZone createdIdZone = db.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        assertEquals(3600, createdIdZone.getConfig().getTokenPolicy().getAccessTokenValidity());
        assertEquals(7200, createdIdZone.getConfig().getTokenPolicy().getRefreshTokenValidity());
    }

    @Test
    public void testCreateIdentityZone_Subdomain_Becomes_LowerCase() throws Exception {
        String subdomain = generator.generate().toUpperCase();
        IdentityZone identityZone = MultitenancyFixture.identityZone(generator.generate(),subdomain);
        identityZone.setId(generator.generate());

        identityZone.setSubdomain(subdomain);
        IdentityZone createdIdZone = db.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(subdomain.toLowerCase(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
    }

    @Test(expected = EmptyResultDataAccessException.class)
    public void test_null_subdomain() {
        db.retrieveBySubdomain(null);
    }

    @Test
    public void testUpdateIdentityZone() throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone(generator.generate(), generator.generate());
        identityZone.setId(generator.generate());

        IdentityZone createdIdZone = db.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());

        String newDomain = new RandomValueStringGenerator().generate();
        createdIdZone.setSubdomain(newDomain);
        createdIdZone.setDescription("new desc");
        createdIdZone.setName("new name");
        IdentityZone updatedIdZone = db.update(createdIdZone);

        assertEquals(createdIdZone.getId(), updatedIdZone.getId());
        assertEquals(createdIdZone.getSubdomain().toLowerCase(), updatedIdZone.getSubdomain());
        assertEquals(createdIdZone.getName(), updatedIdZone.getName());
        assertEquals(createdIdZone.getDescription(), updatedIdZone.getDescription());
    }

    @Test
    public void testUpdateIdentityZone_SubDomain_Is_LowerCase() throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone(generator.generate(),generator.generate());
        identityZone.setId(generator.generate());

        IdentityZone createdIdZone = db.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());

        String newDomain = new RandomValueStringGenerator().generate();
        createdIdZone.setSubdomain(newDomain.toUpperCase());
        createdIdZone.setDescription("new desc");
        createdIdZone.setName("new name");
        IdentityZone updatedIdZone = db.update(createdIdZone);

        assertEquals(createdIdZone.getId(), updatedIdZone.getId());
        assertEquals(createdIdZone.getSubdomain().toLowerCase(), updatedIdZone.getSubdomain());
        assertEquals(createdIdZone.getName(), updatedIdZone.getName());
        assertEquals(createdIdZone.getDescription(), updatedIdZone.getDescription());
    }

    @Test(expected = ZoneDoesNotExistsException.class)
    public void testUpdateNonExistentIdentityZone() throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone(generator.generate(),generator.generate());
        identityZone.setId(generator.generate());
        db.update(identityZone);
    }

    @Test
    public void testCreateDuplicateIdentityZone() throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone("there-can-be-only-one","there-can-be-only-one");
        identityZone.setId(generator.generate());
        db.create(identityZone);
        try {
            db.create(identityZone);
            fail("Should have thrown exception");
        } catch (ZoneAlreadyExistsException e) {
            // success
        }
    }

    @Test
    public void testCreateDuplicateIdentityZoneSubdomain() throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone("there-can-be-only-one","there-can-be-only-one");
        identityZone.setId(generator.generate());
        db.create(identityZone);
        try {
            identityZone.setId(new RandomValueStringGenerator().generate());
            db.create(identityZone);
            fail("Should have thrown exception");
        } catch (ZoneAlreadyExistsException e) {
            // success
        }
    }

}
