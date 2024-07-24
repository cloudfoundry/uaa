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
import java.util.List;
import java.util.function.UnaryOperator;

@Slf4j
public class RelyingPartyRegistrationBuilder {

    private static final UnaryOperator<String> assertionConsumerServiceLocationFunction = "{baseUrl}/saml/SSO/alias/%s"::formatted;
    private static final UnaryOperator<String> singleLogoutServiceResponseLocationFunction = "{baseUrl}/saml/SingleLogout/alias/%s"::formatted;
    private static final UnaryOperator<String> singleLogoutServiceLocationFunction = "{baseUrl}/saml/SingleLogout/alias/%s"::formatted;

    private RelyingPartyRegistrationBuilder() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * @param samlEntityID the entityId of the relying party
     * @param samlSpNameId the nameIdFormat of the relying party
     * @param keys a list of KeyWithCert objects, with the first key in the list being the active key, all keys in the
     *             list will be added for signing. Although it is possible to have multiple decryption keys,
     *             only the first one will be used to maintain parity with existing UAA
     * @param metadataLocation the location or XML data of the metadata
     * @param rpRegistrationId the registrationId of the relying party
     * @param samlSpAlias the alias of the relying party for the SAML endpoints
     * @param requestSigned whether the AuthnRequest should be signed
     * @return a RelyingPartyRegistration object
     */
    public static RelyingPartyRegistration buildRelyingPartyRegistration(
            String samlEntityID, String samlSpNameId,
            List<KeyWithCert> keys, String metadataLocation,
            String rpRegistrationId, String samlSpAlias, boolean requestSigned) {

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
        if (rpRegistrationId != null) builder.registrationId(rpRegistrationId);
        if (samlSpNameId != null) builder.nameIdFormat(samlSpNameId);

        return builder
                .signingX509Credentials(cred ->
                        keys.stream()
                                .map(k -> Saml2X509Credential.signing(k.getPrivateKey(), k.getCertificate()))
                                .forEach(cred::add)
                )
                .decryptionX509Credentials(cred -> keys.stream()
                        .findFirst()
                        .map(k -> Saml2X509Credential.decryption(k.getPrivateKey(), k.getCertificate()))
                        .ifPresent(cred::add)
                )
                .assertionConsumerServiceLocation(assertionConsumerServiceLocationFunction.apply(samlSpAlias))
                .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
                .singleLogoutServiceLocation(singleLogoutServiceLocationFunction.apply(samlSpAlias))
                .singleLogoutServiceResponseLocation(singleLogoutServiceResponseLocationFunction.apply(samlSpAlias))
                // Accept both POST and REDIRECT bindings
                .singleLogoutServiceBindings(c -> {
                    c.add(Saml2MessageBinding.POST);
                    c.add(Saml2MessageBinding.REDIRECT);
                })
                // alter the default value of the APs wantAuthnRequestsSigned,
                // to reflect the UAA configured desire to always sign/or-not the AuthnRequest
                .assertingPartyDetails(details -> details.wantAuthnRequestsSigned(requestSigned))
                .build();
    }
}
