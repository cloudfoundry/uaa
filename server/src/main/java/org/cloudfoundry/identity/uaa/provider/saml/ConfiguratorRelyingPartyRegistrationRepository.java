package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.ZoneAware;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.util.Assert;

import java.util.List;
import java.util.Optional;

@Slf4j
public class ConfiguratorRelyingPartyRegistrationRepository extends BaseUaaRelyingPartyRegistrationRepository
        implements RelyingPartyRegistrationRepository, ZoneAware {

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
     */
    @Override
    public RelyingPartyRegistration findByRegistrationId(String registrationId) {
        IdentityZone currentZone = retrieveZone();
        List<SamlIdentityProviderDefinition> identityProviderDefinitions = configurator.getIdentityProviderDefinitionsForZone(currentZone);
        for (SamlIdentityProviderDefinition identityProviderDefinition : identityProviderDefinitions) {
            if (identityProviderDefinition.getIdpEntityAlias().equals(registrationId)) {

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
        return null;
    }
}
