package org.cloudfoundry.identity.uaa.provider.saml.idp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;
import java.util.UUID;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.context.SAMLMessageContext;

public class IdpWebSsoProfileImplTest {

    private final SamlTestUtils samlTestUtils = new SamlTestUtils();

    @Before
    public void setup() throws ConfigurationException {
        samlTestUtils.initalize();
    }

    @Test
    public void testBuildResponseForSamlRequestWithPersistentNameID() throws MessageEncodingException, SAMLException,
            MetadataProviderException, SecurityException, MarshallingException, SignatureException {
        IdpWebSsoProfileImpl profile = new IdpWebSsoProfileImpl();

        String authenticationId = UUID.randomUUID().toString();
        Authentication authentication = samlTestUtils.mockUaaAuthentication(authenticationId);
        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext(
                samlTestUtils.mockAuthnRequest(NameIDType.PERSISTENT));

        IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
        options.setAssertionsSigned(false);
        profile.buildResponse(authentication, context, options);

        AuthnRequest request = (AuthnRequest) context.getInboundSAMLMessage();
        Response response = (Response) context.getOutboundSAMLMessage();
        Assertion assertion = response.getAssertions().get(0);
        Subject subject = assertion.getSubject();
        assertEquals(authenticationId, subject.getNameID().getValue());
        assertEquals(NameIDType.PERSISTENT, subject.getNameID().getFormat());

        SubjectConfirmation subjectConfirmation = subject.getSubjectConfirmations().get(0);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
        assertEquals(request.getID(), subjectConfirmationData.getInResponseTo());

        verifyAssertionAttributes(authenticationId, assertion);
    }

    @Test
    public void testBuildResponseForSamlRequestWithUnspecifiedNameID() throws MessageEncodingException, SAMLException,
            MetadataProviderException, SecurityException, MarshallingException, SignatureException {
        IdpWebSsoProfileImpl profile = new IdpWebSsoProfileImpl();

        String authenticationId = UUID.randomUUID().toString();
        Authentication authentication = samlTestUtils.mockUaaAuthentication(authenticationId);
        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext(
                samlTestUtils.mockAuthnRequest(NameIDType.UNSPECIFIED));

        IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
        options.setAssertionsSigned(false);
        profile.buildResponse(authentication, context, options);

        AuthnRequest request = (AuthnRequest) context.getInboundSAMLMessage();
        Response response = (Response) context.getOutboundSAMLMessage();
        Assertion assertion = response.getAssertions().get(0);
        Subject subject = assertion.getSubject();
        assertEquals("marissa", subject.getNameID().getValue());
        assertEquals(NameIDType.UNSPECIFIED, subject.getNameID().getFormat());

        SubjectConfirmation subjectConfirmation = subject.getSubjectConfirmations().get(0);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
        assertEquals(request.getID(), subjectConfirmationData.getInResponseTo());

        verifyAssertionAttributes(authenticationId, assertion);
    }

    @Test
    public void testBuildResponseForSamlRequestWithEmailAddressNameID() throws MessageEncodingException, SAMLException,
            MetadataProviderException, SecurityException, MarshallingException, SignatureException {
        IdpWebSsoProfileImpl profile = new IdpWebSsoProfileImpl();

        String authenticationId = UUID.randomUUID().toString();
        Authentication authentication = samlTestUtils.mockUaaAuthentication(authenticationId);
        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext(
                samlTestUtils.mockAuthnRequest(NameIDType.EMAIL));

        IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
        options.setAssertionsSigned(false);
        profile.buildResponse(authentication, context, options);

        AuthnRequest request = (AuthnRequest) context.getInboundSAMLMessage();
        Response response = (Response) context.getOutboundSAMLMessage();
        Assertion assertion = response.getAssertions().get(0);
        Subject subject = assertion.getSubject();
        assertEquals("marissa@testing.org", subject.getNameID().getValue());
        assertEquals(NameIDType.EMAIL, subject.getNameID().getFormat());

        SubjectConfirmation subjectConfirmation = subject.getSubjectConfirmations().get(0);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
        assertEquals(request.getID(), subjectConfirmationData.getInResponseTo());

        verifyAssertionAttributes(authenticationId, assertion);
    }

    @Test
    public void testBuildResponse() throws MessageEncodingException, SAMLException, MetadataProviderException,
            SecurityException, MarshallingException, SignatureException {
        IdpWebSsoProfileImpl profile = new IdpWebSsoProfileImpl();

        String authenticationId = UUID.randomUUID().toString();
        Authentication authentication = samlTestUtils.mockUaaAuthentication(authenticationId);
        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext();

        IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
        options.setAssertionsSigned(false);
        profile.buildResponse(authentication, context, options);

        AuthnRequest request = (AuthnRequest) context.getInboundSAMLMessage();
        Response response = (Response) context.getOutboundSAMLMessage();
        assertEquals(request.getID(), response.getInResponseTo());

        Assertion assertion = response.getAssertions().get(0);
        Subject subject = assertion.getSubject();
        assertEquals("marissa", subject.getNameID().getValue());
        assertEquals(NameIDType.UNSPECIFIED, subject.getNameID().getFormat());

        SubjectConfirmation subjectConfirmation = subject.getSubjectConfirmations().get(0);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
        assertEquals(request.getID(), subjectConfirmationData.getInResponseTo());

        verifyAssertionAttributes(authenticationId, assertion);
    }

    private void verifyAssertionAttributes(String authenticationId, Assertion assertion) {
        List<Attribute> attributes = assertion.getAttributeStatements().get(0).getAttributes();
        assertAttributeValue(attributes, "email", "marissa@testing.org");
        assertAttributeValue(attributes, "id", authenticationId);
        assertAttributeValue(attributes, "name", "marissa");
        assertAttributeValue(attributes, "origin", OriginKeys.UAA);
        assertAttributeValue(attributes, "zoneId", "uaa");
    }

    private void assertAttributeValue(List<Attribute> attributeList, String name, String expectedValue) {

        for (Attribute attribute : attributeList) {
            if (attribute.getName().equals(name)) {
                if (1 != attribute.getAttributeValues().size()) {
                    Assert.fail(String.format("More than one attribute value with name of '%s'.", name));
                }
                XSString xsString = (XSString) attribute.getAttributeValues().get(0);
                Assert.assertEquals(String.format("Attribute mismatch for '%s'.", name), expectedValue,
                        xsString.getValue());
                return;
            }
        }

        Assert.fail(String.format("No attribute value with name of '%s'.", name));
    }

    @Test
    public void testBuildResponseWithSignedAssertion() throws MessageEncodingException, SAMLException,
            MetadataProviderException, SecurityException, MarshallingException, SignatureException {
        IdpWebSsoProfileImpl profile = new IdpWebSsoProfileImpl();

        String authenticationId = UUID.randomUUID().toString();
        Authentication authentication = samlTestUtils.mockUaaAuthentication(authenticationId);
        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext();

        IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
        options.setAssertionsSigned(true);
        profile.buildResponse(authentication, context, options);

        AuthnRequest request = (AuthnRequest) context.getInboundSAMLMessage();
        Response response = (Response) context.getOutboundSAMLMessage();
        Assertion assertion = response.getAssertions().get(0);
        Subject subject = assertion.getSubject();
        assertEquals("marissa", subject.getNameID().getValue());

        SubjectConfirmation subjectConfirmation = subject.getSubjectConfirmations().get(0);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
        assertEquals(request.getID(), subjectConfirmationData.getInResponseTo());

        verifyAssertionAttributes(authenticationId, assertion);

        assertNotNull(assertion.getSignature());
    }

}
