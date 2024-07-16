package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

/**
 * A {@link RelyingPartyRegistrationRepository} that always returns a default {@link RelyingPartyRegistrationRepository}.
 */
public class DefaultRelyingPartyRegistrationRepository extends BaseUaaRelyingPartyRegistrationRepository {
    public static final String CLASSPATH_DUMMY_SAML_IDP_METADATA_XML = "classpath:dummy-saml-idp-metadata.xml";

    public DefaultRelyingPartyRegistrationRepository(String uaaWideSamlEntityID,
                                                     String uaaWideSamlEntityIDAlias,
                                                     KeyWithCert keyWithCert) {
        super(keyWithCert, uaaWideSamlEntityID, uaaWideSamlEntityIDAlias);
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
        IdentityZone currentZone = retrieveZone();

        boolean requestSigned = true;
        if (currentZone.getConfig() != null && currentZone.getConfig().getSamlConfig() != null) {
            requestSigned = currentZone.getConfig().getSamlConfig().isRequestSigned();
        }

        String zonedSamlEntityID = getZoneEntityId(currentZone);
        String zonedSamlEntityIDAlias = getZoneEntityIdAlias(currentZone);

        return RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(
                zonedSamlEntityID, null,
                keyWithCert, CLASSPATH_DUMMY_SAML_IDP_METADATA_XML, registrationId,
                zonedSamlEntityIDAlias, requestSigned);
    }
}
