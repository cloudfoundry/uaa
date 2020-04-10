package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Assert;
import org.junit.Test;

public class SamlRedirectUtilsTest {

    @Test
    public void testGetIdpRedirectUrl() {
        SamlIdentityProviderDefinition definition =
            new SamlIdentityProviderDefinition()
                .setMetaDataLocation("http://some.meta.data")
                .setIdpEntityAlias("simplesamlphp-url")
                .setNameID("nameID")
                .setMetadataTrustCheck(true)
                .setLinkText("link text")
                .setZoneId(IdentityZone.getUaaZoneId());

        String domain = "login.random-made-up-url.com";
        String url = SamlRedirectUtils.getIdpRedirectUrl(definition, domain, IdentityZoneHolder.get());
        Assert.assertEquals("saml/discovery?returnIDParam=idp&entityID=" + domain + "&idp=simplesamlphp-url&isPassive=true", url);
    }
}
