package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.login.AddBcProvider;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.SamlKeyManagerFactory;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.AssertionMarshaller;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.security.saml.metadata.MetadataGenerator;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Random;
import java.util.UUID;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.opensaml.common.xml.SAMLConstants.SAML20P_NS;

public class SamlTestUtils {

    public static final String PROVIDER_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIICXQIBAAKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5\n" +
        "L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vA\n" +
        "fpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQAB\n" +
        "AoGAVOj2Yvuigi6wJD99AO2fgF64sYCm/BKkX3dFEw0vxTPIh58kiRP554Xt5ges\n" +
        "7ZCqL9QpqrChUikO4kJ+nB8Uq2AvaZHbpCEUmbip06IlgdA440o0r0CPo1mgNxGu\n" +
        "lhiWRN43Lruzfh9qKPhleg2dvyFGQxy5Gk6KW/t8IS4x4r0CQQD/dceBA+Ndj3Xp\n" +
        "ubHfxqNz4GTOxndc/AXAowPGpge2zpgIc7f50t8OHhG6XhsfJ0wyQEEvodDhZPYX\n" +
        "kKBnXNHzAkEAyCA76vAwuxqAd3MObhiebniAU3SnPf2u4fdL1EOm92dyFs1JxyyL\n" +
        "gu/DsjPjx6tRtn4YAalxCzmAMXFSb1qHfwJBAM3qx3z0gGKbUEWtPHcP7BNsrnWK\n" +
        "vw6By7VC8bk/ffpaP2yYspS66Le9fzbFwoDzMVVUO/dELVZyBnhqSRHoXQcCQQCe\n" +
        "A2WL8S5o7Vn19rC0GVgu3ZJlUrwiZEVLQdlrticFPXaFrn3Md82ICww3jmURaKHS\n" +
        "N+l4lnMda79eSp3OMmq9AkA0p79BvYsLshUJJnvbk76pCjR28PK4dV1gSDUEqQMB\n" +
        "qy45ptdwJLqLJCeNoR0JUcDNIRhOCuOPND7pcMtX6hI/\n" +
        "-----END RSA PRIVATE KEY-----";

    public static final String PROVIDER_PRIVATE_KEY_PASSWORD = "password";

    public static final String PROVIDER_CERTIFICATE = "-----BEGIN CERTIFICATE-----\n" +
        "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEO\n" +
        "MAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEO\n" +
        "MAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5h\n" +
        "cnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwx\n" +
        "CzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAM\n" +
        "BgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAb\n" +
        "BgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GN\n" +
        "ADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39W\n" +
        "qS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOw\n" +
        "znoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4Ha\n" +
        "MIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGc\n" +
        "gBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYD\n" +
        "VQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYD\n" +
        "VQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJh\n" +
        "QGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ\n" +
        "0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxC\n" +
        "KdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkK\n" +
        "RpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n" +
        "-----END CERTIFICATE-----";

    public static final String SP_ENTITY_ID = "unit-test-sp";
    public static final String IDP_ENTITY_ID = "unit-test-idp";
    protected XMLObjectBuilderFactory builderFactory;

    public void initializeSimple() throws ConfigurationException {
        builderFactory = Configuration.getBuilderFactory();
    }
    public void initialize() throws ConfigurationException {
        AddBcProvider.noop();
        DefaultBootstrap.bootstrap();
        initializeSimple();
    }
    
    public IdentityZone getUaaZoneWithSamlConfig() {
        IdentityZone uaa = IdentityZoneHolder.getUaaZone();
        setupZoneWithSamlConfig(uaa);
        return uaa;
    }
    
    public void setupZoneWithSamlConfig(IdentityZone zone) {
        SamlConfig config = zone.getConfig().getSamlConfig();
        config.setPrivateKey(PROVIDER_PRIVATE_KEY);
        config.setPrivateKeyPassword(PROVIDER_PRIVATE_KEY_PASSWORD);
        config.setCertificate(PROVIDER_CERTIFICATE);
    }

    public static SamlIdentityProviderDefinition createLocalSamlIdpDefinition(String alias, String zoneId, String idpMetaData) {
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
        def.setZoneId(zoneId);
        def.setMetaDataLocation(idpMetaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setAssertionConsumerIndex(0);
        def.setMetadataTrustCheck(false);
        def.setShowSamlLink(true);
        if (StringUtils.isNotEmpty(zoneId) && !zoneId.equals(OriginKeys.UAA)) {
            def.setIdpEntityAlias(zoneId + "." + alias);
            def.setLinkText("Login with Local SAML IdP(" + zoneId + "." + alias + ")");
        } else {
            def.setIdpEntityAlias(alias);
            def.setLinkText("Login with Local SAML IdP(" + alias + ")");
        }
        return def;
    }

    @SuppressWarnings("unchecked")
    public SAMLMessageContext mockSamlMessageContext() {
        return mockSamlMessageContext(mockAuthnRequest());
    }

    @SuppressWarnings("unchecked")
    public SAMLMessageContext mockSamlMessageContext(AuthnRequest authnRequest) {
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
        context.setInboundSAMLMessage(authnRequest);

        KeyManager keyManager = SamlKeyManagerFactory.getKeyManager(PROVIDER_PRIVATE_KEY, PROVIDER_PRIVATE_KEY_PASSWORD, PROVIDER_CERTIFICATE);
        context.setLocalSigningCredential(keyManager.getDefaultCredential());
        return context;
    }

    public EntityDescriptor mockIdpMetadata() {
        return mockIdpMetadataGenerator().generateMetadata();
    }
    
    public IdpMetadataGenerator mockIdpMetadataGenerator() {
        IdpExtendedMetadata extendedMetadata = new IdpExtendedMetadata();

        IdpMetadataGenerator metadataGenerator = new IdpMetadataGenerator();
        metadataGenerator.setEntityId(IDP_ENTITY_ID);
        metadataGenerator.setEntityBaseURL("http://localhost:8080/uaa/saml/idp");
        metadataGenerator.setExtendedMetadata(extendedMetadata);

        KeyManager keyManager = mock(KeyManager.class);
        when(keyManager.getDefaultCredentialName()).thenReturn(null);
        metadataGenerator.setKeyManager(keyManager);
        return metadataGenerator;
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
        return mockAuthnRequest(null);
    }

    public Assertion mockAssertion(String issuerEntityId, String format, String username, String spEndpoint, String audienceEntityID, String privateKey, String keyPassword, String certificate) throws MessageEncodingException, SAMLException,
    MetadataProviderException, SecurityException, MarshallingException, SignatureException  {
        String authenticationId = UUID.randomUUID().toString();
        Authentication authentication = mockUaaAuthentication(authenticationId);
        SAMLMessageContext context = mockSamlMessageContext();
        IdpWebSsoProfileImpl profile = new IdpWebSsoProfileImpl();
        IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
        options.setAssertionsSigned(false);
        profile.buildResponse(authentication, context, options);
        Response response = (Response) context.getOutboundSAMLMessage();
        Assertion assertion = response.getAssertions().get(0);
        DateTime until = new DateTime().plusHours(1);
        assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setRecipient(spEndpoint);
        assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).setAudienceURI(audienceEntityID);
        assertion.getIssuer().setValue(issuerEntityId);
        assertion.getSubject().getNameID().setValue(username);
        assertion.getSubject().getNameID().setFormat(format);
        assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setInResponseTo(null);
        assertion.getSubject().getSubjectConfirmations().get(0).getSubjectConfirmationData().setNotOnOrAfter(until);
        assertion.getConditions().setNotOnOrAfter(until);
        KeyManager keyManager = SamlKeyManagerFactory.getKeyManager(privateKey, keyPassword, certificate);
        SignatureBuilder signatureBuilder = (SignatureBuilder) builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME);
        Signature signature = signatureBuilder.buildObject();
        signature.setSigningCredential(keyManager.getDefaultCredential());
        SecurityHelper.prepareSignatureParams(signature, keyManager.getDefaultCredential(), null, null);
        assertion.setSignature(signature);
        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(assertion);
        marshaller.marshall(assertion);
        Signer.signObject(signature);
        return assertion;
    }

    public static String assertion = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><saml2:Assertion ID=\"agfe71gig53hfe2ggc3427i31bd94\" IssueInstant=\"2017-01-24T22:24:32.000Z\" Version=\"2.0\" xmlns:saml2=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\">\t\t<saml2:Issuer>dnd.login.identity.cf-app.com</saml2:Issuer>\t\t<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">\t\t\t<ds:SignedInfo>\t\t\t\t<ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\t\t\t\t<ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\t\t\t\t<ds:Reference URI=\"#agfe71gig53hfe2ggc3427i31bd94\">\t\t\t\t\t<ds:Transforms>\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\t\t\t\t\t\t<ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\">\t\t\t\t\t\t\t<ec:InclusiveNamespaces PrefixList=\"xs\" xmlns:ec=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>\t\t\t\t\t\t</ds:Transform>\t\t\t\t\t</ds:Transforms>\t\t\t\t\t<ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\t\t\t\t\t<ds:DigestValue>qUU2CHdJFMoySxOWd0QxVAcrzz8=</ds:DigestValue>\t\t\t\t</ds:Reference>\t\t\t</ds:SignedInfo>\t\t\t<ds:SignatureValue>0q3OjHdv4EaOl2FUOSSAQDDb+Cfg9bEJ+RVvbYQHLhzgWHENwD1MDOg8pPMIkQ2zTH8aOg5FKT1qSK2K61NIk+pAZ/L47lJ6V2CCUwfb9lIOsbwATWppUjlg7zmcEXvL8cr/CrPA2q0h1vjT05SbFuUbVmPJ9YXa7PyPHt39XxM=</ds:SignatureValue>\t\t\t<ds:KeyInfo>\t\t\t\t<ds:X509Data>\t\t\t\t\t<ds:X509Certificate>MIIEJTCCA46gAwIBAgIJANIqfxWTfhpkMA0GCSqGSIb3DQEBBQUAMIG+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEdMBsGA1UEChMUUGl2b3RhbCBTb2Z0d2FyZSBJbmMxJDAiBgNVBAsTG0Nsb3VkIEZvdW5kcnkgSWRlbnRpdHkgVGVhbTEcMBoGA1UEAxMTaWRlbnRpdHkuY2YtYXBwLmNvbTEfMB0GCSqGSIb3DQEJARYQbWFyaXNzYUB0ZXN0Lm9yZzAeFw0xNTA1MTQxNzE5MTBaFw0yNTA1MTExNzE5MTBaMIG+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEdMBsGA1UEChMUUGl2b3RhbCBTb2Z0d2FyZSBJbmMxJDAiBgNVBAsTG0Nsb3VkIEZvdW5kcnkgSWRlbnRpdHkgVGVhbTEcMBoGA1UEAxMTaWRlbnRpdHkuY2YtYXBwLmNvbTEfMB0GCSqGSIb3DQEJARYQbWFyaXNzYUB0ZXN0Lm9yZzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA30y2nX+kICXktl1yJhBzLGvtTuzJiLeOMWi++zdivifyRqX1dwJ5MgdOsBWdNrASwe4ZKONiyLFRDsk7lAYq3f975chxSsrRu1BLetBZfPEmwBH7FCTdYtWklJbpz0vzQs/gSsMChT/UrN6zSJhPVHNizLxstedyxxVVts644U8CAwEAAaOCAScwggEjMB0GA1UdDgQWBBSvWY/TyHysYGxKvII95wD/CzE1AzCB8wYDVR0jBIHrMIHogBSvWY/TyHysYGxKvII95wD/CzE1A6GBxKSBwTCBvjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBGcmFuY2lzY28xHTAbBgNVBAoTFFBpdm90YWwgU29mdHdhcmUgSW5jMSQwIgYDVQQLExtDbG91ZCBGb3VuZHJ5IElkZW50aXR5IFRlYW0xHDAaBgNVBAMTE2lkZW50aXR5LmNmLWFwcC5jb20xHzAdBgkqhkiG9w0BCQEWEG1hcmlzc2FAdGVzdC5vcmeCCQDSKn8Vk34aZDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GBAL5j1JCN5EoXMOOBSBUL8KeVZFQD3NfyYkYKBatFEKdBFlAKLBdG+5KzE7sTYesn7EzBISHXFz3DhdK2tg+IF1DeSFVmFl2niVxQ1sYjo4kCugHBsWo+MpFH9VBLFzsMlP3eIDuVKe8aPXFKYCGhctZEJdQTKljalshe50nayKrT</ds:X509Certificate>\t\t\t\t</ds:X509Data>\t\t\t</ds:KeyInfo>\t\t</ds:Signature>\t\t<saml2:Subject>\t\t\t<saml2:NameID Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">fhanik@pivotal.io</saml2:NameID>\t\t\t<saml2:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\t\t\t\t<saml2:SubjectConfirmationData InResponseTo=\"a26j1hhg7f23j3ab9fhd3b89c44ddf\" NotOnOrAfter=\"2017-01-24T22:34:32.001Z\" Recipient=\"https://login.identity.cf-app.com/saml/SSO/alias/login.identity.cf-app.com\"/>\t\t\t</saml2:SubjectConfirmation>\t\t</saml2:Subject>\t\t<saml2:Conditions NotBefore=\"2017-01-24T22:24:32.000Z\" NotOnOrAfter=\"2017-01-24T22:34:32.000Z\">\t\t\t<saml2:AudienceRestriction>\t\t\t\t<saml2:Audience>login.identity.cf-app.com</saml2:Audience>\t\t\t</saml2:AudienceRestriction>\t\t</saml2:Conditions>\t\t<saml2:AuthnStatement AuthnInstant=\"2017-01-24T22:24:32.000Z\" SessionIndex=\"a40ff3hh5e8fifg851b9e19i757b983\">\t\t\t<saml2:AuthnContext>\t\t\t\t<saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml2:AuthnContextClassRef>\t\t\t</saml2:AuthnContext>\t\t</saml2:AuthnStatement>\t\t<saml2:AttributeStatement>\t\t\t<saml2:Attribute Name=\"authorities\">\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">cloud_controller.user</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">scim.me</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">openid</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">profile</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">roles</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">notification_preferences.read</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">user_attributes</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">uaa.user</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">notification_preferences.write</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">cloud_controller.read</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">password.write</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">approvals.me</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">actuator.read</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">cloud_controller.write</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">cloud_controller_service_permissions.read</saml2:AttributeValue>\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">oauth.approvals</saml2:AttributeValue>\t\t\t</saml2:Attribute>\t\t\t<saml2:Attribute Name=\"email\">\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">fhanik@pivotal.io</saml2:AttributeValue>\t\t\t</saml2:Attribute>\t\t\t<saml2:Attribute Name=\"id\">\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">de53ef3f-0fac-4e0c-a5eb-b6c9752684b4</saml2:AttributeValue>\t\t\t</saml2:Attribute>\t\t\t<saml2:Attribute Name=\"name\">\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">fhanik@pivotal.io</saml2:AttributeValue>\t\t\t</saml2:Attribute>\t\t\t<saml2:Attribute Name=\"origin\">\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">uaa</saml2:AttributeValue>\t\t\t</saml2:Attribute>\t\t\t<saml2:Attribute Name=\"zoneId\">\t\t\t\t<saml2:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">1c7a9bf9-679b-483e-a186-41c850411ee5</saml2:AttributeValue>\t\t\t</saml2:Attribute>\t\t</saml2:AttributeStatement>\t</saml2:Assertion>";

    public String mockAssertionEncoded(Assertion assertion, String issuerEntityID, String format, String username, String spEndpoint, String audienceEntityID) throws Exception {
        return mockAssertionEncoded(assertion == null ? mockAssertion(issuerEntityID, format, username, spEndpoint, audienceEntityID, PROVIDER_PRIVATE_KEY, PROVIDER_PRIVATE_KEY_PASSWORD, PROVIDER_CERTIFICATE) : assertion);
    }
    public String mockAssertionEncoded(Assertion assertion) throws Exception {
        AssertionMarshaller marshaller = new AssertionMarshaller();
        Element plaintextElement = marshaller.marshall(assertion);
        String serializedElement = XMLHelper.nodeToString(plaintextElement);
        return Base64.encodeBase64URLSafeString(serializedElement.getBytes("utf-8"));
    }
    public String mockAssertionEncoded(String issuerEntityID, String format, String username, String spEndpoint, String audienceEntityID) throws Exception {
        return mockAssertionEncoded(null, issuerEntityID, format, username, spEndpoint, audienceEntityID);
    }

    public AuthnRequest mockAuthnRequest(String nameIDFormat) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AuthnRequest> builder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
                .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest request = builder.buildObject();
        request.setVersion(SAMLVersion.VERSION_20);
        request.setID(generateID());
        request.setIssuer(getIssuer(SP_ENTITY_ID));
        request.setVersion(SAMLVersion.VERSION_20);
        request.setIssueInstant(new DateTime());
        if (null != nameIDFormat) {
            NameID nameID = ((SAMLObjectBuilder<NameID>) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME))
                    .buildObject();
            nameID.setFormat(nameIDFormat);
            Subject subject = ((SAMLObjectBuilder<Subject>) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME))
                    .buildObject();
            subject.setNameID(nameID);
            request.setSubject(subject);
        }
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
                    + "%s"
                    + "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login\" index=\"0\" isDefault=\"true\"/>"
                    + "<md:AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact\" Location=\"http://localhost:8080/uaa/saml/SSO/alias/cloudfoundry-saml-login\" index=\"1\"/>"
                + "</md:SPSSODescriptor>"
            + "</md:EntityDescriptor>";

    public static final String UNSIGNED_SAML_SP_METADATA_WITHOUT_SPSSODESCRIPTOR = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" ID=\"%s\" entityID=\"cloudfoundry-saml-login\">"
                + "</md:EntityDescriptor>";


    public static final String DEFAULT_NAME_ID_FORMATS =
            "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>"
                    + "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName</md:NameIDFormat>";

    public static final String UNSIGNED_SAML_SP_METADATA_WITHOUT_HEADER = UNSIGNED_SAML_SP_METADATA_WITHOUT_ID.replace("<?xml version=\"1.0\" encoding=\"UTF-8\"?>", "");

    public static final String MOCK_SP_ENTITY_ID = "mock-saml-sp-entity-id";

    public static SamlServiceProvider mockSamlServiceProviderForZone(String zoneId) {
        SamlServiceProviderDefinition singleAddDef = SamlServiceProviderDefinition.Builder.get()
                .setMetaDataLocation(String.format(SamlTestUtils.UNSIGNED_SAML_SP_METADATA_ID_AND_ENTITY_ID,
                        new RandomValueStringGenerator().generate(), MOCK_SP_ENTITY_ID, DEFAULT_NAME_ID_FORMATS))
                .setNameID("sample-nameID").setSingleSignOnServiceIndex(1)
                .setMetadataTrustCheck(true).build();

        return new SamlServiceProvider().setEntityId(MOCK_SP_ENTITY_ID).setIdentityZoneId(zoneId)
                .setConfig(singleAddDef);
    }

    public static SamlServiceProvider mockSamlServiceProvider(String entityId) {
        return mockSamlServiceProvider(entityId, DEFAULT_NAME_ID_FORMATS);
    }

    public static SamlServiceProvider mockSamlServiceProvider(String entityId, String nameIdFormatsXML) {
        SamlServiceProviderDefinition singleAddDef = SamlServiceProviderDefinition.Builder.get()
                .setMetaDataLocation(String.format(SamlTestUtils.UNSIGNED_SAML_SP_METADATA_ID_AND_ENTITY_ID,
                        new RandomValueStringGenerator().generate(), entityId, nameIdFormatsXML))
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

    public static SamlServiceProvider mockSamlServiceProviderForZoneWithoutSPSSOInMetadata(String zoneId) {
        SamlServiceProviderDefinition singleAddDef = SamlServiceProviderDefinition.Builder.get()
                .setMetaDataLocation(String.format(SamlTestUtils.UNSIGNED_SAML_SP_METADATA_ID_AND_ENTITY_ID,
                        new RandomValueStringGenerator().generate(), MOCK_SP_ENTITY_ID, DEFAULT_NAME_ID_FORMATS))
                .setMetadataTrustCheck(true).build();
        return new SamlServiceProvider().setEntityId(MOCK_SP_ENTITY_ID).setIdentityZoneId(zoneId)
                .setConfig(singleAddDef);
     }

}
