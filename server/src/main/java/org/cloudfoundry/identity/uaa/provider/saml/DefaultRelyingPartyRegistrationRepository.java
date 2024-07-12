package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.ZoneAware;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

/**
 * A {@link RelyingPartyRegistrationRepository} that always returns a default {@link RelyingPartyRegistrationRepository}.
 */
public class DefaultRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository, ZoneAware {
    public static final String CLASSPATH_DUMMY_SAML_IDP_METADATA_XML = "classpath:dummy-saml-idp-metadata.xml";

    private final KeyWithCert keyWithCert;
    private final String samlEntityID;

    private final String samlEntityIDAlias; // TODO consider renaming this to indicate UAA wide

    public DefaultRelyingPartyRegistrationRepository(String samlEntityID,
                                                     String samlEntityIDAlias,
                                                     KeyWithCert keyWithCert) {
        this.keyWithCert = keyWithCert;
        this.samlEntityID = samlEntityID;
        this.samlEntityIDAlias = samlEntityIDAlias;
    }

    /**
     * Returns the relying party registration identified by the provided
     * {@code registrationId}, or {@code null} if not found.
     *
     * @param registrationId the registration identifier
     * @return the {@link RelyingPartyRegistration} if found, otherwise {@code null}
     */
    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        IdentityZone zone = retrieveZone();

        boolean requestSigned = true;
        if (zone.getConfig() != null && zone.getConfig().getSamlConfig() != null) {
            requestSigned = zone.getConfig().getSamlConfig().isRequestSigned();
        }

        String zonedSamlEntityID;
        if (!zone.isUaa() && zone.getConfig() != null && zone.getConfig().getSamlConfig() != null && zone.getConfig().getSamlConfig().getEntityID() != null) {
            zonedSamlEntityID = zone.getConfig().getSamlConfig().getEntityID();
        } else {
            zonedSamlEntityID = this.samlEntityID;
        }

        // TODO is this repeating code?
        String zonedSamlEntityIDAlias;
        if (zone.isUaa()) { // default zone
            zonedSamlEntityIDAlias = samlEntityIDAlias;
        } else { // non-default zone
            zonedSamlEntityIDAlias = "%s.%s".formatted(zone.getSubdomain(), samlEntityIDAlias);
        }

        return RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(
                zonedSamlEntityID, null,
                keyWithCert, CLASSPATH_DUMMY_SAML_IDP_METADATA_XML, registrationId,
                zonedSamlEntityIDAlias, requestSigned);
    }
}
