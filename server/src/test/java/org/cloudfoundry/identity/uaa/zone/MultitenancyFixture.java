package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;

public class MultitenancyFixture {

    public static IdentityZone identityZone(String id, String subdomain) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(subdomain.toLowerCase());
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    public static <D extends AbstractIdentityProviderDefinition> IdentityProvider<D> identityProvider(String originKey, String zoneId) {
        IdentityProvider<D> idp = new IdentityProvider<>();
        idp.setName(originKey + " name");
        idp.setOriginKey(originKey);
        idp.setType(originKey + " type");
        idp.setIdentityZoneId(zoneId);
        return idp;
    }
}
