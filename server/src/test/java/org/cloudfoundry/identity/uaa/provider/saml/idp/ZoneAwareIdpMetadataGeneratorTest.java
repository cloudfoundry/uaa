package org.cloudfoundry.identity.uaa.provider.saml.idp;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class ZoneAwareIdpMetadataGeneratorTest {

    public static final String ZONE_ID = "zone-id";
    private ZoneAwareIdpMetadataGenerator generator;
    private IdentityZone otherZone;
    private IdentityZoneConfiguration otherZoneDefinition;

    @Before
    public void setup() {
        otherZone = new IdentityZone();
        otherZone.setId(ZONE_ID);
        otherZone.setName(ZONE_ID);
        otherZone.setSubdomain(ZONE_ID);
        otherZone.setConfig(new IdentityZoneConfiguration());
        otherZoneDefinition = otherZone.getConfig();
        otherZoneDefinition.getSamlConfig().setRequestSigned(true);
        otherZoneDefinition.getSamlConfig().setWantAssertionSigned(true);

        otherZone.setConfig(otherZoneDefinition);

        generator = new ZoneAwareIdpMetadataGenerator();
    }

    @After
    public void clear() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void testWantRequestSigned() {
        generator.setWantAuthnRequestSigned(false);
        assertFalse(generator.isWantAuthnRequestSigned());

        generator.setWantAuthnRequestSigned(true);
        assertTrue(generator.isWantAuthnRequestSigned());

        IdentityZoneHolder.set(otherZone);

        assertFalse(generator.isWantAuthnRequestSigned());
    }
}
