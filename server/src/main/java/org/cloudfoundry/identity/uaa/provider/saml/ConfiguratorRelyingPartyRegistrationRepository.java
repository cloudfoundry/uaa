package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
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
public class ConfiguratorRelyingPartyRegistrationRepository
        implements RelyingPartyRegistrationRepository, ZoneAware {

    private final SamlIdentityProviderConfigurator configurator;
    private final KeyWithCert keyWithCert;
    private final String samlEntityID;

    private final String samlEntityIDAlias;

    public ConfiguratorRelyingPartyRegistrationRepository(String samlEntityID,
                                                          String samlEntityIDAlias,
                                                          KeyWithCert keyWithCert,
                                                          SamlIdentityProviderConfigurator configurator) {
        Assert.notNull(configurator, "configurator cannot be null");
        this.configurator = configurator;
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
        IdentityZone currentZone = retrieveZone();
        List<SamlIdentityProviderDefinition> identityProviderDefinitions = configurator.getIdentityProviderDefinitionsForZone(currentZone);
        for (SamlIdentityProviderDefinition identityProviderDefinition : identityProviderDefinitions) {
            if (identityProviderDefinition.getIdpEntityAlias().equals(registrationId)) {
                String zonedSamlEntityID = getZoneEntityId(currentZone);
                String zonedSamlEntityAlias = getZoneEntityAlias(currentZone);
                boolean requestSigned = currentZone.getConfig().getSamlConfig().isRequestSigned();

                return RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(
                        zonedSamlEntityID, identityProviderDefinition.getNameID(),
                        keyWithCert, identityProviderDefinition.getMetaDataLocation(),
                        registrationId, zonedSamlEntityAlias, requestSigned);
            }
        }
        return null;
    }

    private String getZoneEntityId(IdentityZone currentZone) {
        // for default zone, use the samlEntityID
        if (currentZone.isUaa() ) {
            return samlEntityID;
        }

        // for non-default zone, use the zone specific entityID, if it exists
        return Optional.ofNullable(currentZone.getConfig().getSamlConfig().getEntityID())
                // otherwise use the zone subdomain + default entityID
                .orElseGet(() -> "%s.%s".formatted(currentZone.getSubdomain(), samlEntityID));
    }

    private String getZoneEntityAlias(IdentityZone currentZone) {
        String alias = Optional.ofNullable(samlEntityIDAlias)
                .orElse(samlEntityID);
        // for default zone, use the samlEntityIDAlias, if it exists, otherwise samlEntityID
        if (currentZone.isUaa()) {
            return alias;
        }
        // for non-default zone, use the zone subdomain . samlEntityIDAlias(if it exists, otherwise samlEntityID)
        return "%s.%s".formatted(currentZone.getSubdomain(), alias);
    }
}
