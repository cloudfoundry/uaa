package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.commons.io.IOUtils;
//import org.hsqldb.lib.StringInputStream;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.hsqldb.lib.StringInputStream;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
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

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.io.ByteArrayInputStream;
import java.io.IOException;
//import java.io.StringInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;

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

    @Value("${login.saml.signRequest: true}")
    private Boolean samlSignRequest;

    @Bean
    RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() throws CertificateException, NoSuchAlgorithmException, InvalidKeySpecException {

        String CLASSPATH_DUMMY_SAML_IDP_METADATA_XML = "classpath:dummy-saml-idp-metadata.xml";

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

        IdentityZoneConfiguration config = new IdentityZoneConfiguration();

        String privateKeyString = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICXAIBAAKBgQCpnqPQiDCfJY1hVaQUZG6Rs1Wd3FmP1EStN71hXeXOLog5nvpa\n" +
                "H45P3v79EGpaO06vH5qSu/xr6kQRBOA4h9OqXGS72BGQBH8jMNCoHqgJrIADQTHX\n" +
                "H85RYF38bH6Ycp18jch0KVmYwKeiaLNfMDngnAv6wMDONJz761GBtrG1/wIDAQAB\n" +
                "AoGAPjYeNSzOUICwcyO7E3Omji/tVgHso3EiYznPbvfGgrHUavXhMs7iHm9WrLCp\n" +
                "oUChYl/ADNOACICayHc2WeWPfxJ26BF0ahTzOX1fJsg++JDweCYCNN2WrrYcyA9o\n" +
                "XDU18IFh2dY2CvPL8G7ex5WEq9nYTASQzRfC899nTvUSTyECQQDZddRhqF9g6Zc9\n" +
                "vuSjwQf+dMztsvhLVPAPaSdgE4LMa4nE2iNC/sLq1uUEwrrrOKGaFB9IXeIU7hPW\n" +
                "2QmgJewxAkEAx65IjpesMEq+zE5qRPYkfxjdaa0gNBCfATEBGI4bTx37cKskf49W\n" +
                "2qFlombE9m9t/beYXVC++2W40i53ov+pLwJALRp0X4EFr1sjxGnIkHJkDxH4w0CA\n" +
                "oVdPp1KfGR1S3sVbQNohwC6JDR5fR/p/vHP1iLituFvInaC3urMvfOkAsQJBAJg9\n" +
                "0gYdr+O16Vi95JoljNf2bkG3BJmNnp167ln5ZurgcieJ5K7464CPk3zJnBxEAvlx\n" +
                "dFKZULM98DcXxJFbGXMCQC2ZkPFgzMlRwYu4gake2ruOQR9N3HzLoau1jqDrgh6U\n" +
                "Ow3ylw8RWPq4zmLkDPn83DFMBquYsg3yzBPi7PANBO4=\n" +
                "-----END RSA PRIVATE KEY-----\n";


//        SamlConfig samlConfig = config.getSamlConfig();
//        samlConfig.setPrivateKey(privateKey);
//        KeyFactory factoryInstance = KeyFactory.getInstance("RSA384");
//        SamlKeyManagerFactory.

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(
                new BigInteger("57791d5430d593164082036ad8b29fb157791d5430d593164082036ad8b29fb157791d5430d593164082036ad8b29fb157791d5430d593164082036ad8b29fb1", 16),
                new BigInteger("57791d5430d593164082036ad8b29fb157791d5430d593164082036ad8b29fb157791d5430d593164082036ad8b29fb157791d5430d593164082036ad8b29fb1", 16)
        );

        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        X509Certificate finalCert = cert;
        RelyingPartyRegistration relyingPartyRegistration = RelyingPartyRegistrations
                .fromMetadataLocation(CLASSPATH_DUMMY_SAML_IDP_METADATA_XML)
                .entityId(samlEntityID)
                .nameIdFormat(samlSpNameID)
                .registrationId("example")
                .assertingPartyDetails(details -> details
                        .wantAuthnRequestsSigned(samlSignRequest)
//                        .signingAlgorithms((sign) -> sign.add(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1))  // 512 by default?
                        )
                .signingX509Credentials( (cred) -> cred
                        .add(Saml2X509Credential.signing( privateKey, finalCert)
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
