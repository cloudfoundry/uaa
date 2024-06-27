package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.util.Assert;

import java.util.List;

@Slf4j
public class ConfiguratorRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {

    private final SamlIdentityProviderConfigurator configurator;
    private final KeyWithCert keyWithCert;
    private final Boolean samlSignRequest;
    private final String samlEntityID;

    public ConfiguratorRelyingPartyRegistrationRepository(Boolean samlSignRequest,
                                                          @Qualifier("samlEntityID") String samlEntityID,
                                                          KeyWithCert keyWithCert,
                                                          SamlIdentityProviderConfigurator configurator) {
        Assert.notNull(configurator, "configurator cannot be null");
        this.configurator = configurator;
        this.keyWithCert = keyWithCert;
        this.samlSignRequest = samlSignRequest;
        this.samlEntityID = samlEntityID;
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
        List<SamlIdentityProviderDefinition> identityProviderDefinitions = configurator.getIdentityProviderDefinitions();
        for (SamlIdentityProviderDefinition identityProviderDefinition : identityProviderDefinitions) {
            if (identityProviderDefinition.getIdpEntityAlias().equals(registrationId)) {
                return RelyingPartyRegistrationBuilder.buildRelyingPartyRegistration(
                        samlEntityID, identityProviderDefinition.getNameID(), samlSignRequest,
                        keyWithCert, identityProviderDefinition.getMetaDataLocation(), registrationId);
            }
        }
        return null;
    }
}
