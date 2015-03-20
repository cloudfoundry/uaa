package org.cloudfoundry.identity.uaa.zone;

import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

public class JdbcIdentityZoneProvisioningTests extends JdbcTestBase {

    private JdbcIdentityZoneProvisioning db;

    @Before
    public void createDatasource() throws Exception {
        db = new JdbcIdentityZoneProvisioning(jdbcTemplate);
    }

    @Test
    public void testCreateIdentityZone() throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(),UUID.randomUUID().toString());
        identityZone.setId(UUID.randomUUID().toString());

        IdentityZone createdIdZone = db.create(identityZone);

        assertEquals(identityZone.getId(), createdIdZone.getId());
        assertEquals(identityZone.getSubdomain(), createdIdZone.getSubdomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
    }

    @Test
    public void testUpdateIdentityZone() throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(),UUID.randomUUID().toString());
        identityZone.setId(UUID.randomUUID().toString());

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
        assertEquals(createdIdZone.getSubdomain(), updatedIdZone.getSubdomain());
        assertEquals(createdIdZone.getName(), updatedIdZone.getName());
        assertEquals(createdIdZone.getDescription(), updatedIdZone.getDescription());
    }

    @Test(expected = ZoneDoesNotExistsException.class)
    public void testUpdateNonExistentIdentityZone() throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone(UUID.randomUUID().toString(),UUID.randomUUID().toString());
        identityZone.setId(UUID.randomUUID().toString());
        db.update(identityZone);
    }

    @Test
    public void testCreateDuplicateIdentityZone() throws Exception {
        IdentityZone identityZone = MultitenancyFixture.identityZone("there-can-be-only-one","there-can-be-only-one");
        identityZone.setId(UUID.randomUUID().toString());
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
        identityZone.setId(UUID.randomUUID().toString());
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
