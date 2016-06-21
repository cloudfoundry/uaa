package org.cloudfoundry.identity.uaa.provider.saml.idp;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.opensaml.common.xml.SAMLConstants.SAML20P_NS;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Random;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.AddBcProvider;
import org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactory;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;

public class SamlTestUtils {

    public static final String PROVIDER_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n"
            + "MIICXQIBAAKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5\n"
            + "L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vA\n"
            + "fpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQAB\n"
            + "AoGAVOj2Yvuigi6wJD99AO2fgF64sYCm/BKkX3dFEw0vxTPIh58kiRP554Xt5ges\n"
            + "7ZCqL9QpqrChUikO4kJ+nB8Uq2AvaZHbpCEUmbip06IlgdA440o0r0CPo1mgNxGu\n"
            + "lhiWRN43Lruzfh9qKPhleg2dvyFGQxy5Gk6KW/t8IS4x4r0CQQD/dceBA+Ndj3Xp\n"
            + "ubHfxqNz4GTOxndc/AXAowPGpge2zpgIc7f50t8OHhG6XhsfJ0wyQEEvodDhZPYX\n"
            + "kKBnXNHzAkEAyCA76vAwuxqAd3MObhiebniAU3SnPf2u4fdL1EOm92dyFs1JxyyL\n"
            + "gu/DsjPjx6tRtn4YAalxCzmAMXFSb1qHfwJBAM3qx3z0gGKbUEWtPHcP7BNsrnWK\n"
            + "vw6By7VC8bk/ffpaP2yYspS66Le9fzbFwoDzMVVUO/dELVZyBnhqSRHoXQcCQQCe\n"
            + "A2WL8S5o7Vn19rC0GVgu3ZJlUrwiZEVLQdlrticFPXaFrn3Md82ICww3jmURaKHS\n"
            + "N+l4lnMda79eSp3OMmq9AkA0p79BvYsLshUJJnvbk76pCjR28PK4dV1gSDUEqQMB\n"
            + "qy45ptdwJLqLJCeNoR0JUcDNIRhOCuOPND7pcMtX6hI/\n" + "-----END RSA PRIVATE KEY-----";

    public static final String PROVIDER_PRIVATE_KEY_PASSWORD = "password";

    public static final String PROVIDER_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEO\n"
            + "MAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEO\n"
            + "MAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5h\n"
            + "cnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwx\n"
            + "CzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAM\n"
            + "BgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAb\n"
            + "BgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GN\n"
            + "ADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39W\n"
            + "qS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOw\n"
            + "znoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4Ha\n"
            + "MIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGc\n"
            + "gBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYD\n"
            + "VQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYD\n"
            + "VQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJh\n"
            + "QGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ\n"
            + "0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxC\n"
            + "KdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkK\n"
            + "RpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n" + "-----END CERTIFICATE-----\n";

    public static final String SP_ENTITY_ID = "unit-test-sp";
    public static final String IDP_ENTITY_ID = "unit-test-idp";
    private XMLObjectBuilderFactory builderFactory;

    public void initalize() throws ConfigurationException {
        IdentityZone.getUaa().getConfig().getSamlConfig().setPrivateKey(PROVIDER_PRIVATE_KEY);
        IdentityZone.getUaa().getConfig().getSamlConfig().setPrivateKeyPassword(PROVIDER_PRIVATE_KEY_PASSWORD);
        IdentityZone.getUaa().getConfig().getSamlConfig().setCertificate(PROVIDER_CERTIFICATE);
        AddBcProvider.noop();
        DefaultBootstrap.bootstrap();
        builderFactory = Configuration.getBuilderFactory();
    }

    @SuppressWarnings("unchecked")
    public SAMLMessageContext mockSamlMessageContext() {
        SAMLMessageContext context = new SAMLMessageContext();

        context.setLocalEntityId(IDP_ENTITY_ID);
        context.setLocalEntityRole(IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
        EntityDescriptor idpMetadata = mockIdpMetadata();
        context.setLocalEntityMetadata(idpMetadata);
        IDPSSODescriptor idpDescriptor = idpMetadata.getIDPSSODescriptor(SAML20P_NS);
        context.setLocalEntityRoleMetadata(idpDescriptor);

        context.setPeerEntityId(SP_ENTITY_ID);
        context.setPeerEntityRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        EntityDescriptor spMetadata = mockSpMetadata();
        context.setPeerEntityMetadata(spMetadata);
        SPSSODescriptor spDescriptor = spMetadata.getSPSSODescriptor(SAML20P_NS);
        context.setPeerEntityRoleMetadata(spDescriptor);

        AuthnRequest authnRequest = mockAuthnRequest();
        context.setInboundSAMLMessage(authnRequest);

        KeyManager keyManager = SamlKeyManagerFactory.getKeyManager(PROVIDER_PRIVATE_KEY, PROVIDER_PRIVATE_KEY_PASSWORD, PROVIDER_CERTIFICATE);
        context.setLocalSigningCredential(keyManager.getDefaultCredential());
        return context;
    }

    public EntityDescriptor mockIdpMetadata() {
        IdpExtendedMetadata extendedMetadata = new IdpExtendedMetadata();

        IdpMetadataGenerator metadataGenerator = new IdpMetadataGenerator();
        metadataGenerator.setEntityId(IDP_ENTITY_ID);
        metadataGenerator.setEntityBaseURL("http://localhost:8080/uaa/saml/idp");
        metadataGenerator.setExtendedMetadata(extendedMetadata);

        KeyManager keyManager = mock(KeyManager.class);
        when(keyManager.getDefaultCredentialName()).thenReturn(null);
        metadataGenerator.setKeyManager(keyManager);
        return metadataGenerator.generateMetadata();
    }

    public EntityDescriptor mockSpMetadata() {
        ExtendedMetadata extendedMetadata = new ExtendedMetadata();

        MetadataGenerator metadataGenerator = new MetadataGenerator();
        metadataGenerator.setExtendedMetadata(extendedMetadata);
        metadataGenerator.setEntityId(SP_ENTITY_ID);
        metadataGenerator.setEntityBaseURL("http://localhost:8080/uaa/saml");
        metadataGenerator.setWantAssertionSigned(false);

        KeyManager keyManager = mock(KeyManager.class);
        when(keyManager.getDefaultCredentialName()).thenReturn(null);
        metadataGenerator.setKeyManager(keyManager);
        return metadataGenerator.generateMetadata();
    }

    public AuthnRequest mockAuthnRequest() {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AuthnRequest> builder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
                .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest request = builder.buildObject();
        request.setVersion(SAMLVersion.VERSION_20);
        request.setID(generateID());
        request.setIssuer(getIssuer(SP_ENTITY_ID));
        request.setVersion(SAMLVersion.VERSION_20);
        request.setIssueInstant(new DateTime());
        return request;
    }

    public String generateID() {
        Random r = new Random();
        return 'a' + Long.toString(Math.abs(r.nextLong()), 20) + Long.toString(Math.abs(r.nextLong()), 20);
    }

    public Issuer getIssuer(String localEntityId) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
                .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(localEntityId);
        return issuer;
    }

    public UaaAuthentication mockUaaAuthenticationWithSamlMessageContext(SAMLMessageContext context) {
        UaaAuthentication uaaAuthentication = mockUaaAuthentication();
        when(uaaAuthentication.getSamlMessageContext()).thenReturn(context);
        return uaaAuthentication;
    }

    public UaaAuthentication mockUaaAuthentication() {
        return mockUaaAuthentication(UUID.randomUUID().toString());
    }

    public UaaAuthentication mockUaaAuthentication(String id) {
        UaaAuthentication authentication = mock(UaaAuthentication.class);
        when(authentication.getName()).thenReturn("marissa");

        UaaPrincipal principal = new UaaPrincipal(id, "marissa", "marissa@testing.org",
                OriginKeys.UAA, "marissa", "uaa");
        when(authentication.getPrincipal()).thenReturn(principal);

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(UaaAuthority.UAA_USER);
        doReturn(authorities).when(authentication).getAuthorities();

        return authentication;
    }

    public static final String SAML_SP_METADATA = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"cloudfoundry-saml-login\" entityID=\"cloudfoundry-saml-login\">"
                + "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                    + "<ds:SignedInfo>"
                        + "<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                        + "<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>"
                        + "<ds:Reference URI=\"#cloudfoundry-saml-login\">"
                            + "<ds:Transforms>"
                                + "<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>"
                                + "<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
                            + "</ds:Transforms>"
                            + "<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
                            + "<ds:DigestValue>mPb/c/Gb/PN61JNRptMgHbK9L08=</ds:DigestValue>"
                        + "</ds:Reference>"
                    + "</ds:SignedInfo>"
                    + "<ds:SignatureValue>Ra6mE3hjN68Jwk6D3DktVrOu0BXJCSPTMr0YTgQyII8fv7j93BhuGMoZHw48tww6N9zkUDEuy+uRp9vd4gepxs8+XiL+kvoclMAStmzJ62/2fGuI3hCvht2lBXIuFBpZab3iuqxBhwceLnsvvsM5y4nfYDXuBS1XGRzrygLbldM=</ds:SignatureValue>"
                    + "<ds:KeyInfo>"
                        + "<ds:X509Data>"
                            + "<ds:X509Certificate>"
                                + "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF"
                                + "YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM"
                                + "BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2"
                                + "MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE"
                                + "ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx"
                                + "HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
                                + "gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR"
                                + "4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY"
                                + "xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy"
                                + "GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3"
                                + "MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL"
                                + "EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA"
                                + "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am"
                                + "2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o"
                                + "ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="
                            + "</ds:X509Certificate>"
                        + "</ds:X509Data>"
                    + "</ds:KeyInfo>"
                + "</ds:Signature>"
                + "<md:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
                    + "<md:KeyDescriptor use=\"signing\">"
                        + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                            + "<ds:X509Data>"
                                + "<ds:X509Certificate>"
                                    + "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF"
                                    + "YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM"
                                    + "BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2"
                                    + "MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE"
                                    + "ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx"
                                    + "HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
                                    + "gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR"
                                    + "4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY"
                                    + "xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy"
                                    + "GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3"
                                    + "MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL"
                                    + "EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA"
                                    + "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am"
                                    + "2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o"
                                    + "ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="
                                + "</ds:X509Certificate>"
                            + "</ds:X509Data>"
                        + "</ds:KeyInfo>"
                    + "</md:KeyDescriptor>"
                    + "<md:KeyDescriptor use=\"encryption\">"
                        + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                            + "<ds:X509Data>"
                                + "<ds:X509Certificate>"
                                    + "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF"
                                    + "YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM"
                                    + "BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2"
                                    + "MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE"
                                    + "ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx"
                                    + "HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
                                    + "gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR"
                                    + "4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY"
                                    + "xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy"
                                    + "GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3"
                                    + "MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL"
                                    + "EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA"
                                    + "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am"
                                    + "2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o"
                                    + "ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="
                                + "</ds:X509Certificate>"
                            + "</ds:X509Data>"
                        + "</ds:KeyInfo>"
                    + "</md:KeyDescriptor>"
                    + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/uaa/saml/SingleLogout/alias/cloudfoundry-saml-login\"/>"
                    + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/uaa/saml/SingleLogout/alias/cloudfoundry-saml-login\"/>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat>"
                    + "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login\" index=\"0\" isDefault=\"true\"/>"
                    + "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login\" index=\"1\"/>"
                + "</md:SPSSODescriptor>"
            + "</md:EntityDescriptor>";

    public static final String UNSIGNED_SAML_SP_METADATA = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"cloudfoundry-saml-login\" entityID=\"cloudfoundry-saml-login\">"
                + "<md:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
                    + "<md:KeyDescriptor use=\"signing\">"
                        + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                            + "<ds:X509Data>"
                                + "<ds:X509Certificate>"
                                    + "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF"
                                    + "YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM"
                                    + "BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2"
                                    + "MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE"
                                    + "ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx"
                                    + "HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
                                    + "gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR"
                                    + "4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY"
                                    + "xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy"
                                    + "GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3"
                                    + "MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL"
                                    + "EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA"
                                    + "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am"
                                    + "2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o"
                                    + "ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="
                                + "</ds:X509Certificate>"
                            + "</ds:X509Data>"
                        + "</ds:KeyInfo>"
                    + "</md:KeyDescriptor>"
                    + "<md:KeyDescriptor use=\"encryption\">"
                        + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                            + "<ds:X509Data>"
                                + "<ds:X509Certificate>"
                                    + "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF"
                                    + "YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM"
                                    + "BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2"
                                    + "MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE"
                                    + "ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx"
                                    + "HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
                                    + "gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR"
                                    + "4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY"
                                    + "xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy"
                                    + "GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3"
                                    + "MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL"
                                    + "EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA"
                                    + "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am"
                                    + "2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o"
                                    + "ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="
                                + "</ds:X509Certificate>"
                            + "</ds:X509Data>"
                        + "</ds:KeyInfo>"
                    + "</md:KeyDescriptor>"
                    + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/uaa/saml/SingleLogout/alias/cloudfoundry-saml-login\"/>"
                    + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/uaa/saml/SingleLogout/alias/cloudfoundry-saml-login\"/>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat>"
                    + "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login\" index=\"0\" isDefault=\"true\"/>"
                    + "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login\" index=\"1\"/>"
                + "</md:SPSSODescriptor>"
            + "</md:EntityDescriptor>";

    public static final String UNSIGNED_SAML_SP_METADATA_WITHOUT_ID = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"%s\" entityID=\"cloudfoundry-saml-login\">"
                + "<md:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
                    + "<md:KeyDescriptor use=\"signing\">"
                        + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                            + "<ds:X509Data>"
                                + "<ds:X509Certificate>"
                                    + "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF"
                                    + "YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM"
                                    + "BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2"
                                    + "MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE"
                                    + "ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx"
                                    + "HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
                                    + "gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR"
                                    + "4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY"
                                    + "xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy"
                                    + "GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3"
                                    + "MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL"
                                    + "EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA"
                                    + "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am"
                                    + "2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o"
                                    + "ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="
                                + "</ds:X509Certificate>"
                            + "</ds:X509Data>"
                        + "</ds:KeyInfo>"
                    + "</md:KeyDescriptor>"
                    + "<md:KeyDescriptor use=\"encryption\">"
                        + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                            + "<ds:X509Data>"
                                + "<ds:X509Certificate>"
                                    + "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF"
                                    + "YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM"
                                    + "BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2"
                                    + "MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE"
                                    + "ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx"
                                    + "HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
                                    + "gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR"
                                    + "4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY"
                                    + "xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy"
                                    + "GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3"
                                    + "MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL"
                                    + "EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA"
                                    + "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am"
                                    + "2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o"
                                    + "ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="
                                + "</ds:X509Certificate>"
                            + "</ds:X509Data>"
                        + "</ds:KeyInfo>"
                    + "</md:KeyDescriptor>"
                    + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/uaa/saml/SingleLogout/alias/cloudfoundry-saml-login\"/>"
                    + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/uaa/saml/SingleLogout/alias/cloudfoundry-saml-login\"/>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat>"
                    + "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login\" index=\"0\" isDefault=\"true\"/>"
                    + "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login\" index=\"1\"/>"
                + "</md:SPSSODescriptor>"
            + "</md:EntityDescriptor>";

    public static final String UNSIGNED_SAML_SP_METADATA_ID_AND_ENTITY_ID = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"%s\" entityID=\"%s\">"
                + "<md:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
                    + "<md:KeyDescriptor use=\"signing\">"
                        + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                            + "<ds:X509Data>"
                                + "<ds:X509Certificate>"
                                    + "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF"
                                    + "YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM"
                                    + "BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2"
                                    + "MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE"
                                    + "ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx"
                                    + "HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
                                    + "gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR"
                                    + "4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY"
                                    + "xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy"
                                    + "GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3"
                                    + "MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL"
                                    + "EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA"
                                    + "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am"
                                    + "2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o"
                                    + "ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="
                                + "</ds:X509Certificate>"
                            + "</ds:X509Data>"
                        + "</ds:KeyInfo>"
                    + "</md:KeyDescriptor>"
                    + "<md:KeyDescriptor use=\"encryption\">"
                        + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                            + "<ds:X509Data>"
                                + "<ds:X509Certificate>"
                                    + "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEOMAwGA1UECBMF"
                                    + "YXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEOMAwGA1UECxMFYXJ1YmExDjAM"
                                    + "BgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5hcnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2"
                                    + "MjdaFw0xNjExMTkyMjI2MjdaMHwxCzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UE"
                                    + "ChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmEx"
                                    + "HTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB"
                                    + "gQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39WqS9u0hnA+O7MCA/KlrAR"
                                    + "4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCY"
                                    + "xhMol6ZnTbSsFW6VZjFMjQIDAQABo4HaMIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1sy"
                                    + "GDCBpwYDVR0jBIGfMIGcgBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3"
                                    + "MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYDVQQL"
                                    + "EwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyggEA"
                                    + "MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ0HOZbbHClXmGUjGs+GS+xC1FO/am"
                                    + "2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxCKdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3o"
                                    + "ePe84k8jm3A7EvH5wi5hvCkKRpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0="
                                + "</ds:X509Certificate>"
                            + "</ds:X509Data>"
                        + "</ds:KeyInfo>"
                    + "</md:KeyDescriptor>"
                    + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/uaa/saml/SingleLogout/alias/cloudfoundry-saml-login\"/>"
                    + "<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"http://localhost:8080/uaa/saml/SingleLogout/alias/cloudfoundry-saml-login\"/>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat>"
                    + "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login\" index=\"0\" isDefault=\"true\"/>"
                    + "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login\" index=\"1\"/>"
                + "</md:SPSSODescriptor>"
            + "</md:EntityDescriptor>";

    public static final String UNSIGNED_SAML_SP_METADATA_WITHOUT_HEADER = UNSIGNED_SAML_SP_METADATA_WITHOUT_ID.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");

    public static final String MOCK_SP_ENTITY_ID = "cloudfoundry-saml-login";

    public static SamlServiceProvider mockSamlServiceProviderForZone(String zoneId) {
        SamlServiceProviderDefinition singleAddDef = SamlServiceProviderDefinition.Builder.get()
                .setMetaDataLocation(String.format(SamlTestUtils.UNSIGNED_SAML_SP_METADATA_WITHOUT_ID,
                        new RandomValueStringGenerator().generate()))
                .setNameID("sample-nameID").setSingleSignOnServiceIndex(1)
                .setMetadataTrustCheck(true).build();
        return new SamlServiceProvider().setEntityId(MOCK_SP_ENTITY_ID).setIdentityZoneId(zoneId)
                .setConfig(singleAddDef);
    }

    public static SamlServiceProvider mockSamlServiceProvider(String entityId) {
        SamlServiceProviderDefinition singleAddDef = SamlServiceProviderDefinition.Builder.get()
                .setMetaDataLocation(String.format(SamlTestUtils.UNSIGNED_SAML_SP_METADATA_ID_AND_ENTITY_ID,
                        new RandomValueStringGenerator().generate(), entityId))
                .setNameID("sample-nameID").setSingleSignOnServiceIndex(1)
                .setMetadataTrustCheck(true).build();
        return new SamlServiceProvider().setEntityId(entityId).setIdentityZoneId("uaa")
                .setConfig(singleAddDef);
    }

    public static SamlServiceProvider mockSamlServiceProviderWithoutXmlHeaderInMetadata() {
        SamlServiceProviderDefinition singleAddWithoutHeaderDef = SamlServiceProviderDefinition.Builder.get()
                .setMetaDataLocation(String.format(SamlTestUtils.UNSIGNED_SAML_SP_METADATA_WITHOUT_HEADER,
                        new RandomValueStringGenerator().generate()))
                .setNameID("sample-nameID").setSingleSignOnServiceIndex(1)
                .setMetadataTrustCheck(true).build();
        return new SamlServiceProvider().setEntityId(MOCK_SP_ENTITY_ID).setIdentityZoneId("uaa")
                .setConfig(singleAddWithoutHeaderDef);
    }
}
