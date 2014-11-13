package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.util.UUID;

import static org.junit.Assert.*;

@ContextConfiguration(locations = { "classpath:spring/env.xml", "classpath:spring/data-source.xml" })
@RunWith(SpringJUnit4ClassRunner.class)
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcIdentityZoneProvisioningTests {

    @Autowired
    private JdbcTemplate template;

    private JdbcIdentityZoneProvisioning db;

    @Before
    public void createDatasource() throws Exception {
        db = new JdbcIdentityZoneProvisioning(template);
    }

    @Test
    public void testCreateIdentityZone() throws Exception {
        IdentityZone identityZone = getIdentityZone(UUID.randomUUID().toString());

        IdentityZone createdIdZone = db.create(identityZone);

        assertEquals(identityZone.getSubDomain(), createdIdZone.getSubDomain());
        assertEquals(identityZone.getName(), createdIdZone.getName());
        assertEquals(identityZone.getDescription(), createdIdZone.getDescription());
        UUID.fromString(createdIdZone.getId());
    }

    @Test
    public void testCreateDuplicateIdentityZone() throws Exception {
        IdentityZone identityZone = getIdentityZone("there-can-be-only-one");
        db.create(identityZone);
        try {
            db.create(identityZone);
            fail("Should have thrown exception");
        } catch (ZoneAlreadyExistsException e) {
            // success
        }
    }

    private IdentityZone getIdentityZone(String serviceInstanceId) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setSubDomain("subdomain-" + serviceInstanceId);
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }
}
