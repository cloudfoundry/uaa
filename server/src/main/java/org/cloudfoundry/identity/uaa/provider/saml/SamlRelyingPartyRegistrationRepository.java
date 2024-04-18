package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.commons.io.IOUtils;
//import org.hsqldb.lib.StringInputStream;
import org.hsqldb.lib.StringInputStream;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrations;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.IOException;
//import java.io.StringInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

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

    @Autowired
    @Qualifier("samlSpNameID")
    private String samlSpNameID;

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() throws CertificateException {

        String CLASSPATH_DUMMY_SAML_IDP_METADATA_XML = "classpath:dummy-saml-idp-metadata.xml";
        String samlEntityID = "integration-saml-entity-id";
        String samlNameIDFormat = "example-NAME_ID_FORMAT";

//        X509Certificate cert = null;
        String certString = new String("-----BEGIN CERTIFICATE-----\nMIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF\n" +
        "                    YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM\n" +
        "                    BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2\n" +
        "                    MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE\n" +
        "                    ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx\n" +
        "                    HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB\n" +
        "                    gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR\n" +
        "                    4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY\n" +
        "                    xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy\n" +
        "                    GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3\n" +
        "                    MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL\n" +
        "                    EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA\n" +
        "                    MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am\n" +
        "                    2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o\n" +
        "                    ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n-----END CERTIFICATE-----");
        InputStream stream = new ByteArrayInputStream(certString.getBytes(StandardCharsets.UTF_8));
        CertificateFactory cf = CertificateFactory. getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf. generateCertificate(stream);

        X509Certificate finalCert = cert;
        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
                .fromMetadataLocation(CLASSPATH_DUMMY_SAML_IDP_METADATA_XML)
                .entityId(samlEntityID)
                .nameIdFormat(samlNameIDFormat)
                .registrationId("example")
                .assertingPartyDetails(details -> details
                        .entityId(samlEntityID)
                        .wantAuthnRequestsSigned(true)
                        .signingAlgorithms((sign) -> sign.add(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1))  // 512 by default?
                        )
                .signingX509Credentials( (cred) -> cred
                        .add(new Saml2X509Credential(finalCert)
                        )
                )
                .build();


//        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
//                .fromMetadataLocation(CLASSPATH_DUMMY_SAML_IDP_METADATA_XML)
//                .entityId(samlEntityID)
//                .nameIdFormat(samlSpNameID)
//                .registrationId("example")
//                .assertingPartyDetails(details -> details
//                        .wantAuthnRequestsSigned(true)
//                        .entityId("TEST_REG_REP")
//                )
//                .assertingPartyDetails(party -> party
//                        .entityId("XXXXXXXXX---" + samlEntityID)
////                        .singleSignOnServiceLocation("https://idp.example.com/SSO.saml2")
//                        .wantAuthnRequestsSigned(true)
////                        .verificationX509Credentials(c -> c.add(credential))
//                )
//                .build();
        return new InMemoryRelyingPartyRegistrationRepository(relyingPartyRegistration);
    }

}
