package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

@DefaultTestContext
class PollutionPreventionExtensionTests {

    @Autowired
    private JdbcIdentityZoneProvisioning jdbcIdentityZoneProvisioning;

    @Autowired
    private MultitenantJdbcClientDetailsService multitenantJdbcClientDetailsService;

    @Test
    void pollutionOfIdentityZoneHolderStaticThreadLocalZoneVariable() {
        IdentityZone identityZone = IdentityZoneHolder.get();
        // Test to see if we were polluted by another test
        assertThat(identityZone.getName()).isEqualTo("uaa");

        // Cause pollution
        identityZone.setName("newName");
    }

    @Test
    void pollutionOfIdentityZoneHolderStaticProvisioningVariable() {
        IdentityZone uaaZone = jdbcIdentityZoneProvisioning.retrieve("uaa");
        uaaZone.setDescription("newDescription");
        jdbcIdentityZoneProvisioning.update(uaaZone);

        // Test to see if we were polluted by another test.
        // The following would fail if IdentityZoneHolder.provisioning is null, because
        // in that case getUaaZone() returns a fresh new uaa zone instance with the default description.
        assertThat(IdentityZoneHolder.getUaaZone().getDescription()).isEqualTo("newDescription");

        // Cause pollution
        IdentityZoneHolder.setProvisioning(null);
    }

    @Test
    void pollutionOfUaaIdentityZoneInTheDatabase() {
        // Test to see if we were polluted by another test.
        // The following line throws an exception when the zone is inactive.
        jdbcIdentityZoneProvisioning.retrieve("uaa");

        // Cause pollution
        IdentityZone uaaZone = jdbcIdentityZoneProvisioning.retrieveIgnoreActiveFlag("uaa");
        uaaZone.setActive(false);
        jdbcIdentityZoneProvisioning.update(uaaZone);
    }

    @Test
    void pollutionOfClientInTheDatabase() {
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
