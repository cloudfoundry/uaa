package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

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
        IdentityZone idZone = new IdentityZone();
        idZone.setServiceInstanceId("service-instance-id");
        idZone.setSubDomain("subdomain.domain.io");
        idZone.setName("twiglet service");

        IdentityZone createdIdZone = db.createZone(idZone);

        assertNotNull(createdIdZone.getId());
        assertEquals("service-instance-id", createdIdZone.getServiceInstanceId());
        assertEquals("subdomain.domain.io", createdIdZone.getSubDomain());
        assertEquals("twiglet service", createdIdZone.getName());
    }
}
