package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.util.Assert;

import java.util.List;

public class ConfiguratorRelyingPartyRegistrationRepository implements RelyingPartyRegistrationRepository {

    private final SamlIdentityProviderConfigurator configurator;
    private final KeyWithCert keyWithCert;
    private final Boolean samlSignRequest;

    public ConfiguratorRelyingPartyRegistrationRepository(Boolean samlSignRequest, KeyWithCert keyWithCert, SamlIdentityProviderConfigurator configurator) {
        Assert.notNull(configurator, "configurator cannot be null");
        this.configurator = configurator;
        this.keyWithCert = keyWithCert;
        this.samlSignRequest = samlSignRequest;
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
                return buildRelyingPartyRegistration(registrationId, identityProviderDefinition);
            }
        }
        return null;
    }

    private RelyingPartyRegistration buildRelyingPartyRegistration(String registrationId, SamlIdentityProviderDefinition def) {
        return RelyingPartyRegistrations
                .fromMetadataLocation(def.getMetaDataLocation())
                .entityId(registrationId)
                .nameIdFormat(def.getNameID())
                .registrationId(registrationId)
                .assertingPartyDetails(details -> details
                        .wantAuthnRequestsSigned(samlSignRequest)
                )
                .signingX509Credentials(cred -> cred
                        .add(Saml2X509Credential.signing(keyWithCert.getPrivateKey(), keyWithCert.getCertificate()))
                )
                .decryptionX509Credentials(cred -> cred
                        .add(Saml2X509Credential.decryption(keyWithCert.getPrivateKey(), keyWithCert.getCertificate()))
                )
                .build();
    }
}
