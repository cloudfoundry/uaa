package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;

import java.util.List;

/**
 * A ZoneAware {@link RelyingPartyRegistrationRepository} that always returns a default
 * {@link RelyingPartyRegistrationRepository}. The default {@link RelyingPartyRegistration} in the
 * {@link SamlRelyingPartyRegistrationRepositoryConfig} is configured to use a dummy SAML IdP metadata
 * for the default zone (named example), this class also provides a dummy SAML IdP RelyingPartyRegistration
 * but for non-default zones.
 */
public class DefaultRelyingPartyRegistrationRepository extends BaseUaaRelyingPartyRegistrationRepository {

    public DefaultRelyingPartyRegistrationRepository(String uaaWideSamlEntityID,
            String uaaWideSamlEntityIDAlias,
            List<SignatureAlgorithm> signatureAlgorithms,
            String uaaWideSamlNameId) {
        super(uaaWideSamlEntityID, uaaWideSamlEntityIDAlias, signatureAlgorithms, uaaWideSamlNameId);
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

        SamlKeyManager samlKeyManager = retrieveKeyManager();
        List<KeyWithCert> keyWithCerts = samlKeyManager.getAvailableCredentials();

        String zonedSamlEntityID = getZoneEntityId(currentZone);
        String zonedSamlEntityIDAlias = getZoneEntityIdAlias(currentZone);

        RelyingPartyRegistrationBuilder.Params params = RelyingPartyRegistrationBuilder.Params.builder()
                .samlEntityID(zonedSamlEntityID)
                .samlSpNameId(uaaWideSamlNameId)
                .keys(keyWithCerts)
                .metadataLocation(RelyingPartyRegistrationBuilder.createOwnMetadata(zonedSamlEntityID, keyWithCerts))
                .rpRegistrationId(registrationId)
                .samlSpAlias(zonedSamlEntityIDAlias)
                .requestSigned(requestSigned)
                .signatureAlgorithms(signatureAlgorithms)
                .build();
        return RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(params);
    }
}
