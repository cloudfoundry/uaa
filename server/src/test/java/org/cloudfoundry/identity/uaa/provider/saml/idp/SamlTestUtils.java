package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;

// Attempt to move usages to Saml2TestUtils style
public final class SamlTestUtils {

    private SamlTestUtils() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static SamlIdentityProviderDefinition createLocalSamlIdpDefinition(String alias, String zoneId, String idpMetaData) {
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setZoneId(zoneId);
        def.setMetaDataLocation(idpMetaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setAssertionConsumerIndex(0);
        def.setMetadataTrustCheck(false);
        def.setShowSamlLink(true);
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals(OriginKeys.UAA)) {
            def.setIdpEntityAlias(zoneId + "." + alias);
            def.setLinkText("Login with Local SAML IdP(" + zoneId + "." + alias + ")");
        } else {
            def.setIdpEntityAlias(alias);
            def.setLinkText("Login with Local SAML IdP(" + alias + ")");
        }
        return def;
    }
}
