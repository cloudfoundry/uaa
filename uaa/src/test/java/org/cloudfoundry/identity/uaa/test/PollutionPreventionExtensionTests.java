package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.SpringServletTestConfig;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.context.WebApplicationContext;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = SpringServletTestConfig.class)
class PollutionPreventionExtensionTests {

    @Autowired
    private WebApplicationContext webApplicationContext;

    @Autowired
    private JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning;

    @Autowired
    private MultitenantJdbcClientDetailsService multitenantJdbcClientDetailsService;

    @Test
    void testPollutionOfIdentityZoneHolderStaticThreadLocalZoneVariable() {
        IdentityZone identityZone = IdentityZoneHolder.get();
        // Test to see if we were polluted by another test
        assertEquals("uaa", identityZone.getName());

        // Cause pollution
        identityZone.setName("newName");
    }

    @Test
    void testPollutionOfIdentityZoneHolderStaticProvisioningVariable() {
        IdentityZone uaaZone = jdbcIdentityZoneProvisioning.retrieve("uaa");
        uaaZone.setDescription("newDescription");
        jdbcIdentityZoneProvisioning.update(uaaZone);

        // Test to see if we were polluted by another test.
        // The following would fail if IdentityZoneHolder.provisioning is null, because
        // in that case getUaaZone() returns a fresh new uaa zone instance with the default description.
        assertEquals("newDescription", IdentityZoneHolder.getUaaZone().getDescription());

        // Cause pollution
        IdentityZoneHolder.setProvisioning(null);
    }

    @Test
    void testPollutionOfUaaIdentityZoneInTheDatabase() {
        // Test to see if we were polluted by another test.
        // The following line throws an exception when the zone is inactive.
        jdbcIdentityZoneProvisioning.retrieve("uaa");

        // Cause pollution
        IdentityZone uaaZone = jdbcIdentityZoneProvisioning.retrieveIgnoreActiveFlag("uaa");
        uaaZone.setActive(false);
        jdbcIdentityZoneProvisioning.update(uaaZone);
    }

    @Test
    void testPollutionOfClientInTheDatabase() {
        // Test to see if we were polluted by another test.
        // The following line throws an exception when the client cannot be found.
        multitenantJdbcClientDetailsService.loadClientByClientId("admin");

        // Cause pollution
        multitenantJdbcClientDetailsService.removeClientDetails("admin");
    }
}

class PollutionPreventionExtensionTestsRunAgainTests extends PollutionPreventionExtensionTests {
    // All tests are inherited here to make them run again from a different class.

    // The tests above are designed to fail when run a second time due to the test pollution
    // which they purposefully cause, unless the PollutionPreventionExtension successfully
    // prevents the pollution between these two test classes.
}
