package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.saml.SamlKey;
import org.cloudfoundry.identity.uaa.util.KeyWithCert;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.stereotype.Component;

import java.security.cert.CertificateException;

@Component
public class SamlRelyingPartyRegistrationRepository {

    // SAML SP metadata generation relies on a relyingPartyRegistration, which requires a valid SAML IDP
    // metadata. In the context of UAA external SAML IDP login, UAA does not know what the SAML IDP
    // metadata is, until the operator adds it via the /identity-providers endpoint. Also, some SAML
    // IDPs might require you to supply the SAML SP metadata first before you can obtain the
    // SAML IDP metadata. Hence, supply a hardcoded dummy SAML IDP metadata here to unblock the SAML
    // SP metadata generation. See relevant issue: https://github.com/spring-projects/spring-security/issues/11369
    public static final String CLASSPATH_DUMMY_SAML_IDP_METADATA_XML = "classpath:dummy-saml-idp-metadata.xml";

    @Autowired
    @Qualifier("samlEntityID")
    private String samlEntityID;

    @Value("${login.saml.nameID:urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified}")
    private String samlSpNameID;

    @Value("${login.saml.signRequest:true}")
    private Boolean samlSignRequest;

    @Autowired
    private SamlConfiguration samlConfiguration;

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() throws CertificateException {

        SamlKey activeSamlKey = samlConfiguration.getActiveSamlKey();
        KeyWithCert keyWithCert = new KeyWithCert(activeSamlKey.getKey(), activeSamlKey.getPassphrase(), activeSamlKey.getCertificate());

        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
                .fromMetadataLocation(CLASSPATH_DUMMY_SAML_IDP_METADATA_XML)
                .entityId(samlEntityID)
                .nameIdFormat(samlSpNameID)
                .registrationId("example")
                .assertingPartyDetails(details -> details
                        .wantAuthnRequestsSigned(samlSignRequest)
                        )
                .signingX509Credentials( cred -> cred
                        .add(Saml2X509Credential.signing( keyWithCert.getPrivateKey(), keyWithCert.getCertificate()))
                )
                .decryptionX509Credentials( cred -> cred
                        .add(Saml2X509Credential.decryption( keyWithCert.getPrivateKey(), keyWithCert.getCertificate()))
                )
                .build();

        return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
    }
}