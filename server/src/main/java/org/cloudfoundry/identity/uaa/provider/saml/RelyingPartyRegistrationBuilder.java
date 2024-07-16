package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.function.UnaryOperator;

@Slf4j
public class RelyingPartyRegistrationBuilder {

    private static final UnaryOperator<String> assertionConsumerServiceLocationFunction = "{baseUrl}/saml/SSO/alias/%s"::formatted;
    private static final UnaryOperator<String> singleLogoutServiceResponseLocationFunction = "{baseUrl}/saml/SingleLogout/alias/%s"::formatted;
    private static final UnaryOperator<String> singleLogoutServiceLocationFunction = "{baseUrl}/saml/SingleLogout/alias/%s"::formatted;

    private RelyingPartyRegistrationBuilder() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static RelyingPartyRegistration buildRelyingPartyRegistration(
            String samlEntityID, String samlSpNameId,
            KeyWithCert keyWithCert, String metadataLocation,
            String rpRegstrationId, String samlSpAlias, boolean requestSigned) {

        SamlIdentityProviderDefinition.MetadataLocation type = SamlIdentityProviderDefinition.getType(metadataLocation);
        RelyingPartyRegistration.Builder builder;
        if (type == SamlIdentityProviderDefinition.MetadataLocation.DATA) {
            try (InputStream stringInputStream = new ByteArrayInputStream(metadataLocation.getBytes())) {
                builder = RelyingPartyRegistrations.fromMetadata(stringInputStream);
            } catch (Exception e) {
                log.error("Error reading metadata from string: {}", metadataLocation, e);
                throw new Saml2Exception(e);
            }
        } else {
            builder = RelyingPartyRegistrations.fromMetadataLocation(metadataLocation);
        }

        builder.entityId(samlEntityID);
        if (samlSpNameId != null) builder.nameIdFormat(samlSpNameId);
        if (rpRegstrationId != null) builder.registrationId(rpRegstrationId);
        return builder
                .assertionConsumerServiceLocation(assertionConsumerServiceLocationFunction.apply(samlSpAlias))
                .singleLogoutServiceResponseLocation(singleLogoutServiceResponseLocationFunction.apply(samlSpAlias))
                .singleLogoutServiceLocation(singleLogoutServiceLocationFunction.apply(samlSpAlias))
                .singleLogoutServiceResponseLocation(singleLogoutServiceResponseLocationFunction.apply(samlSpAlias))
                // Accept both POST and REDIRECT bindings
                .singleLogoutServiceBindings(c -> {
                    c.add(Saml2MessageBinding.REDIRECT);
                    c.add(Saml2MessageBinding.POST);
                })
                .assertingPartyDetails(details -> details
                        .wantAuthnRequestsSigned(requestSigned)
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
