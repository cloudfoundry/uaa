package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.Builder;
import lombok.Value;
import lombok.With;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
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

/**
 * A utility class to build a {@link RelyingPartyRegistration} object from the given parameters
 */
@Slf4j
public class RelyingPartyRegistrationBuilder {
    public static final String CLASSPATH_DUMMY_SAML_IDP_METADATA_XML = "classpath:dummy-saml-idp-metadata.xml";

    private static final UnaryOperator<String> assertionConsumerServiceLocationFunction = "{baseUrl}/saml/SSO/alias/%s"::formatted;
    private static final UnaryOperator<String> singleLogoutServiceResponseLocationFunction = "{baseUrl}/saml/SingleLogout/alias/%s"::formatted;
    private static final UnaryOperator<String> singleLogoutServiceLocationFunction = "{baseUrl}/saml/SingleLogout/alias/%s"::formatted;

    private RelyingPartyRegistrationBuilder() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    /**
     * Build a RelyingPartyRegistration object from the given parameters
     *
     * @param params the params object used to build the RelyingPartyRegistration object
     * @return a RelyingPartyRegistration object
     */
    public static RelyingPartyRegistration buildRelyingPartyRegistration(Params builderParams) {
        final Params params;
        if (StringUtils.isEmpty(builderParams.getMetadataLocation())) {
            params = builderParams.withMetadataLocation(CLASSPATH_DUMMY_SAML_IDP_METADATA_XML);
        } else {
            params = builderParams;
        }

        SamlIdentityProviderDefinition.MetadataLocation type = SamlIdentityProviderDefinition.getType(params.metadataLocation);
        RelyingPartyRegistration.Builder builder;
        if (type == SamlIdentityProviderDefinition.MetadataLocation.DATA) {
            try (InputStream stringInputStream = new ByteArrayInputStream(params.metadataLocation.getBytes())) {
                builder = RelyingPartyRegistrations.fromMetadata(stringInputStream);
            } catch (Exception e) {
                log.error("Error reading metadata from string: {}", params.metadataLocation, e);
                throw new Saml2Exception(e);
            }
        } else {
            builder = RelyingPartyRegistrations.fromMetadataLocation(params.metadataLocation);
        }

        builder.entityId(params.samlEntityID);
        if (params.rpRegistrationId != null) builder.registrationId(params.rpRegistrationId);
        if (params.samlSpNameId != null) builder.nameIdFormat(params.samlSpNameId);

        return builder
                .signingX509Credentials(cred -> params.keys.stream()
                        .map(k -> Saml2X509Credential.signing(k.getPrivateKey(), k.getCertificate()))
                        .forEach(cred::add))
                .decryptionX509Credentials(cred -> params.keys.stream().findFirst()
                        .map(k -> Saml2X509Credential.decryption(k.getPrivateKey(), k.getCertificate()))
                        .ifPresent(cred::add))
                .assertionConsumerServiceLocation(assertionConsumerServiceLocationFunction.apply(params.samlSpAlias))
                .assertionConsumerServiceBinding(Saml2MessageBinding.POST)
                .singleLogoutServiceLocation(singleLogoutServiceLocationFunction.apply(params.samlSpAlias))
                .singleLogoutServiceResponseLocation(singleLogoutServiceResponseLocationFunction.apply(params.samlSpAlias))
                // Accept both POST and REDIRECT bindings
                .singleLogoutServiceBindings(c -> {
                    c.add(Saml2MessageBinding.POST);
                    c.add(Saml2MessageBinding.REDIRECT);
                })
                // alter the default value of the APs wantAuthnRequestsSigned,
                // to reflect the UAA configured desire to always sign/or-not the AuthnRequest
                .assertingPartyDetails(details -> {
                    details.wantAuthnRequestsSigned(params.requestSigned);
                    details.signingAlgorithms(alg -> alg.addAll(params.signatureAlgorithms.stream().map(SignatureAlgorithm::getSignatureAlgorithmURI).toList()));
                }).build();
    }

    /**
     * Parameters for building a {@link RelyingPartyRegistration} using {@link RelyingPartyRegistrationBuilder}
     */
    @Value
    @Builder
    @With
    public static class Params {
        /**
         * the entityId of the relying party
         */
        String samlEntityID;

        /**
         * the nameIdFormat of the relying party
         */
        String samlSpNameId;

        /**
         * A list of KeyWithCert objects, with the first key in the list being the active key, all keys in the
         * list will be added for signing. Although it is possible to have multiple decryption keys,
         * only the first one will be used to maintain parity with existing UAA
         */
        List<KeyWithCert> keys;

        /**
         * the location or XML data of the metadata
         */
        String metadataLocation;

        /**
         * the registrationId of the relying party
         */
        String rpRegistrationId;

        /**
         * the alias of the relying party for the SAML endpoints
         */
        String samlSpAlias;

        /**
         * whether the AuthnRequest should be signed
         */
        boolean requestSigned;

        /**
         * the list of signature algorithms to use for signing
         */
        List<SignatureAlgorithm> signatureAlgorithms;
    }
}
