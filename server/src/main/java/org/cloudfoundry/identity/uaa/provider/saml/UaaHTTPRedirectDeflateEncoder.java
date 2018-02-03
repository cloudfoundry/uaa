package org.cloudfoundry.identity.uaa.provider.saml;

import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.credential.Credential;

public class UaaHTTPRedirectDeflateEncoder extends HTTPRedirectDeflateEncoder {

    private ZoneAwareSamlSecurityConfiguration zoneAwareSamlSecurityConfiguration;

    public void setZoneAwareSamlSecurityConfiguration(ZoneAwareSamlSecurityConfiguration zoneAwareSamlSecurityConfiguration) {
        this.zoneAwareSamlSecurityConfiguration = zoneAwareSamlSecurityConfiguration;
    }

    @Override
    protected String getSignatureAlgorithmURI(Credential credential, SecurityConfiguration securityConfiguration) throws MessageEncodingException {
        if(securityConfiguration == null) {
            securityConfiguration = this.zoneAwareSamlSecurityConfiguration;
        }
        return super.getSignatureAlgorithmURI(credential, securityConfiguration);
    }
}
