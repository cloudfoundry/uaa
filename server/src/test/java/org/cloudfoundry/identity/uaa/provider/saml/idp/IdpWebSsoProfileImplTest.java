package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.context.SAMLMessageContext;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IdpWebSsoProfileImplTest {

    private final SamlTestUtils samlTestUtils = new SamlTestUtils();
    private JdbcSamlServiceProviderProvisioning samlServiceProviderProvisioning = mock(JdbcSamlServiceProviderProvisioning.class);
    private JdbcScimUserProvisioning scimUserProvisioning = mock(JdbcScimUserProvisioning.class);

    @Before
    public void setup() throws ConfigurationException {
        samlTestUtils.initialize();
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

    @Test
    public void verifyAttributeMappings() throws Exception {
        IdpWebSsoProfileImpl profile = new IdpWebSsoProfileImpl();
        profile.setSamlServiceProviderProvisioning(samlServiceProviderProvisioning);
        profile.setScimUserProvisioning(scimUserProvisioning);

        ScimUser user = new ScimUser(null, "johndoe", "John", "Doe");
        user.setPhoneNumbers(Collections.singletonList(new ScimUser.PhoneNumber("123")));

        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "first_name");
        attributeMappings.put("family_name", "last_name");
        attributeMappings.put("phone_number", "cell_phone");

        SamlServiceProvider sp = new SamlServiceProvider();
        SamlServiceProviderDefinition config = new SamlServiceProviderDefinition();
        config.setAttributeMappings(attributeMappings);
        sp.setConfig(config);

        when(scimUserProvisioning.retrieve(anyString(), anyString())).thenReturn(user);
        when(samlServiceProviderProvisioning.retrieveByEntityId(any(), any())).thenReturn(sp);

        String authenticationId = UUID.randomUUID().toString();
        Authentication authentication = samlTestUtils.mockUaaAuthentication(authenticationId);
        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext(
            samlTestUtils.mockAuthnRequest(NameIDType.UNSPECIFIED));

        IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
        options.setAssertionsSigned(false);
        profile.buildResponse(authentication, context, options);

        Response response = (Response) context.getOutboundSAMLMessage();
        Assertion assertion = response.getAssertions().get(0);

        profile.buildAttributeStatement(assertion, authentication, sp.getEntityId());

        List<Attribute> attributes = assertion.getAttributeStatements().get(0).getAttributes();

        assertAttributeValue(attributes, "first_name", user.getGivenName());
        assertAttributeValue(attributes, "last_name", user.getFamilyName());
        assertAttributeValue(attributes, "cell_phone", user.getPhoneNumbers().get(0).getValue());

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
