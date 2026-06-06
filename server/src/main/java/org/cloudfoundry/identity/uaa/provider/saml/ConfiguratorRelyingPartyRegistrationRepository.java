package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;

import java.util.List;
import java.util.Optional;

@Slf4j
public class ConfiguratorRelyingPartyRegistrationRepository extends BaseUaaRelyingPartyRegistrationRepository {

    private final SamlIdentityProviderConfigurator configurator;

    public ConfiguratorRelyingPartyRegistrationRepository(String uaaWideSamlEntityID,
            String uaaWideSamlEntityIDAlias,
            SamlIdentityProviderConfigurator configurator,
            List<SignatureAlgorithm> signatureAlgorithms,
            String uaaWideSamlNameId) {
        super(uaaWideSamlEntityID, uaaWideSamlEntityIDAlias, signatureAlgorithms, uaaWideSamlNameId);
        Assert.notNull(configurator, "configurator cannot be null");
        this.configurator = configurator;
    }

    /**
     * Returns the relying party registration identified by the provided
     * {@code registrationId}, or {@code null} if not found.
     *
     * @param registrationId the registration identifier
     * @return the {@link RelyingPartyRegistration} if found, otherwise {@code null}
     * @throws Saml2Exception if the registration cannot be built due to invalid or unreachable metadata
     */
    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        IdentityZone currentZone = retrieveZone();
        AbstractIdentityProviderDefinition idpDefinition = configurator.getIdentityProviderDefinitionsForOrigin(currentZone, registrationId);
        if (idpDefinition == null) {
            idpDefinition = configurator.getIdentityProviderDefinitionsForIssuer(currentZone, registrationId);
        }
        try {
            if (idpDefinition instanceof SamlIdentityProviderDefinition foundSamlIdentityProviderDefinition) {
                return createRelyingPartyRegistration(foundSamlIdentityProviderDefinition.getIdpEntityAlias(), foundSamlIdentityProviderDefinition, currentZone);
            }

            for (SamlIdentityProviderDefinition identityProviderDefinition : configurator.getIdentityProviderDefinitionsForZone(currentZone)) {
                if (registrationId.equals(identityProviderDefinition.getIdpEntityAlias())) {
                    return createRelyingPartyRegistration(identityProviderDefinition.getIdpEntityAlias(), identityProviderDefinition, currentZone);
                }
                // idpEntityId is populated from external_key at read time; if external_key was never
                // stored (e.g. URL-type IDPs bootstrapped without idpEntityId being set), fall back
                // to resolving the entity ID dynamically from the metadata.
                String resolvedEntityId = identityProviderDefinition.getIdpEntityId();
                if (resolvedEntityId == null) {
                    try {
                        resolvedEntityId = configurator.getExtendedMetadataDelegate(identityProviderDefinition)
                                .getAssertingPartyMetadata().getEntityId();
                    } catch (Exception e) {
                        log.warn("Could not resolve entity ID from metadata for SAML IDP '{}': {}",
                                identityProviderDefinition.getIdpEntityAlias(), e.getMessage());
                    }
                }
                if (registrationId.equals(resolvedEntityId)) {
                    return createRelyingPartyRegistration(identityProviderDefinition.getIdpEntityAlias(), identityProviderDefinition, currentZone);
                }
            }
        } catch (Exception e) {
            log.warn("Cannot retrieve SAML trusted party for registrationId: {}", registrationId, e);
            throw new Saml2Exception("Unable to build SAML relying party registration for: " + registrationId, e);
        }

        return null;
    }

    private RelyingPartyRegistration createRelyingPartyRegistration(String registrationId, SamlIdentityProviderDefinition identityProviderDefinition, IdentityZone currentZone) {
        SamlKeyManager samlKeyManager = retrieveKeyManager();
        List<KeyWithCert> keyWithCerts = samlKeyManager.getAvailableCredentials();

        String zonedSamlEntityID = getZoneEntityId(currentZone);
        String zonedSamlEntityIDAlias = getZoneEntityIdAlias(currentZone);
        boolean requestSigned = currentZone.getConfig().getSamlConfig().isRequestSigned();
        String nameID = Optional.ofNullable(identityProviderDefinition.getNameID()).orElse(uaaWideSamlNameId);

        RelyingPartyRegistrationBuilder.Params params = RelyingPartyRegistrationBuilder.Params.builder()
                .samlEntityID(zonedSamlEntityID)
                .samlSpNameId(nameID)
                .keys(keyWithCerts)
                .metadataLocation(identityProviderDefinition.getMetaDataLocation())
                .rpRegistrationId(registrationId)
                .samlSpAlias(zonedSamlEntityIDAlias)
                .requestSigned(requestSigned)
                .signatureAlgorithms(signatureAlgorithms)
                .build();
        return RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(params);
    }
}
