package org.cloudfoundry.identity.uaa.zone;

import org.junit.Assert;
import org.junit.Test;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import static org.mockito.Mockito.mock;

public class IdentityZoneSwitchingFilterTests {

    @Test
    public void testStripPrefix() {
        String zoneId = new RandomValueStringGenerator().generate();
        IdentityZoneSwitchingFilter filter = new IdentityZoneSwitchingFilter(mock(IdentityZoneProvisioning.class));
        Assert.assertEquals("zones." + zoneId + ".admin", filter.stripPrefix("zones." + zoneId + ".admin", zoneId));
        Assert.assertEquals("zones." + zoneId + ".read", filter.stripPrefix("zones." + zoneId + ".read", zoneId));
        Assert.assertEquals("clients.admin", filter.stripPrefix("zones." + zoneId + ".clients.admin", zoneId));
        Assert.assertEquals("clients.read", filter.stripPrefix("zones." + zoneId + ".clients.read", zoneId));
        Assert.assertEquals("idps.read", filter.stripPrefix("zones." + zoneId + ".idps.read", zoneId));
    }

}