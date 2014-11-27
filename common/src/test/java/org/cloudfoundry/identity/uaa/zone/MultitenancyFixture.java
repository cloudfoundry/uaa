package org.cloudfoundry.identity.uaa.zone;


public class MultitenancyFixture {
    public static IdentityZone identityZone(String id, String subdomain) {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId(id);
        identityZone.setSubdomain(subdomain);
        identityZone.setName("The Twiglet Zone");
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }
    
    public static IdentityProvider identityProvider(String originKey) {
        IdentityProvider idp = new IdentityProvider();
        idp.setName(originKey+" name");
        idp.setOriginKey(originKey);
        idp.setType(originKey+" type");
        idp.setConfig(originKey+" config");
        return idp;
    }
}
