package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.signature.SignatureException;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml.context.SAMLMessageContext;

import java.util.*;
import java.util.stream.Collectors;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IdpWebSsoProfileImplTest {

    private SamlTestUtils samlTestUtils;
    private JdbcSamlServiceProviderProvisioning samlServiceProviderProvisioning;
    private JdbcScimUserProvisioning scimUserProvisioning;
    private IdpWebSsoProfileImpl profile;
    private ScimUser user;
    private SamlServiceProvider samlServiceProvider;

    @Before
    public void setup() throws ConfigurationException {
        samlTestUtils = new SamlTestUtils();
        samlServiceProviderProvisioning = mock(JdbcSamlServiceProviderProvisioning.class);
        scimUserProvisioning = mock(JdbcScimUserProvisioning.class);
        samlTestUtils.initialize();

        profile = new IdpWebSsoProfileImpl();
        user = new ScimUser(null, "johndoe", "John", "Doe");

        samlServiceProvider = new SamlServiceProvider();
        SamlServiceProviderDefinition config = new SamlServiceProviderDefinition();
        config.setAttributeMappings(new HashMap<>());
        samlServiceProvider.setConfig(config);

        when(scimUserProvisioning.retrieve(any(), any())).thenReturn(user);
        when(samlServiceProviderProvisioning.retrieveByEntityId(any(), any())).thenReturn(samlServiceProvider);
        profile.setScimUserProvisioning(scimUserProvisioning);
        profile.setSamlServiceProviderProvisioning(samlServiceProviderProvisioning);
    }

    @Test
    public void testBuildResponseForSamlRequestWithPersistentNameID() throws Exception {
        String authenticationId = UUID.randomUUID().toString();
        Authentication authentication = samlTestUtils.mockUaaAuthentication(authenticationId);
        SAMLMessageContext context =
            samlTestUtils.mockSamlMessageContext(samlTestUtils.mockAuthnRequest(NameIDType.PERSISTENT));

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
    public void testBuildResponseForSamlRequestWithUnspecifiedNameID() throws SAMLException,
            MetadataProviderException, SecurityException, MarshallingException, SignatureException {
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
    public void testBuildResponseForSamlRequestWithEmailAddressNameID() throws SAMLException,
            MetadataProviderException, SecurityException, MarshallingException, SignatureException {
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
    public void testBuildResponse() throws SAMLException, MetadataProviderException,
            SecurityException, MarshallingException, SignatureException {
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
        String phone = "123";
        user.setPhoneNumbers(Collections.singletonList(new ScimUser.PhoneNumber(phone)));
        user.setPrimaryEmail("marissa@saml-test.org");
        when(scimUserProvisioning.extractPhoneNumber(any(ScimUser.class))).thenReturn(phone);
        Map<String, Object> staticAttributes = new HashMap<>();
        staticAttributes.put("organization-id","12345");
        staticAttributes.put("organization-dba", Arrays.asList("The Org", "Acme Inc"));
        samlServiceProvider.getConfig().setStaticCustomAttributes(staticAttributes);

        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "first_name");
        attributeMappings.put("family_name", "last_name");
        attributeMappings.put("phone_number", "cell_phone");
        attributeMappings.put("email", "primary_email");
        samlServiceProvider.getConfig().setAttributeMappings(attributeMappings);
        String authenticationId = UUID.randomUUID().toString();
        Authentication authentication = samlTestUtils.mockUaaAuthentication(authenticationId);
        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext(
            samlTestUtils.mockAuthnRequest(NameIDType.UNSPECIFIED));
        IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
        options.setAssertionsSigned(false);
        profile.buildResponse(authentication, context, options);
        Response response = (Response) context.getOutboundSAMLMessage();
        Assertion assertion = response.getAssertions().get(0);

        profile.buildAttributeStatement(assertion, authentication, samlServiceProvider.getEntityId());

        List<Attribute> attributes = assertion.getAttributeStatements().get(0).getAttributes();

        assertAttributeValue(attributes, "primary_email", user.getPrimaryEmail());
        assertAttributeValue(attributes, "first_name", user.getGivenName());
        assertAttributeValue(attributes, "last_name", user.getFamilyName());
        assertAttributeValue(attributes, "cell_phone", user.getPhoneNumbers().get(0).getValue());
        assertAttributeValue(attributes, "organization-dba", "The Org", "Acme Inc");
        assertAttributeValue(attributes, "organization-id", "12345");
    }

    @Test
    public void verifyAttributeMappingsIgnoredForNullValues() throws Exception {
        user.setPhoneNumbers(Collections.singletonList(new ScimUser.PhoneNumber(null)));

        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "first_name");
        attributeMappings.put("phone_number", "cell_phone");

        samlServiceProvider.getConfig().setAttributeMappings(attributeMappings);
        String authenticationId = UUID.randomUUID().toString();
        Authentication authentication = samlTestUtils.mockUaaAuthentication(authenticationId);
        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext(
            samlTestUtils.mockAuthnRequest(NameIDType.UNSPECIFIED));
        IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
        options.setAssertionsSigned(false);
        profile.buildResponse(authentication, context, options);
        Response response = (Response) context.getOutboundSAMLMessage();
        Assertion assertion = response.getAssertions().get(0);

        profile.buildAttributeStatement(assertion, authentication, samlServiceProvider.getEntityId());

        List<Attribute> attributes = assertion.getAttributeStatements().get(0).getAttributes();

        assertAttributeValue(attributes, "first_name", user.getGivenName());
        assertAttributeDoesNotExist(attributes, "last_name");
        assertAttributeDoesNotExist(attributes, "cell_phone");
    }

    @Test
    public void testCustomUserAttributes() throws Exception {
        LinkedHashMap<String, String> customAttributes = new LinkedHashMap<>();
        customAttributes.put("accountNumber", "12345");
        user.setCustomAttributes(customAttributes);

        String authenticationId = UUID.randomUUID().toString();
        Authentication authentication = samlTestUtils.mockUaaAuthentication(authenticationId);
        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext(
                samlTestUtils.mockAuthnRequest(NameIDType.UNSPECIFIED));
        IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
        options.setAssertionsSigned(false);
        profile.buildResponse(authentication, context, options);
        Response response = (Response) context.getOutboundSAMLMessage();
        Assertion assertion = response.getAssertions().get(0);

        profile.buildAttributeStatement(assertion, authentication, samlServiceProvider.getEntityId());

        List<Attribute> attributes = assertion.getAttributeStatements().get(0).getAttributes();

        assertAttributeValue(attributes, "accountNumber", user.getCustomAttributes().get("accountNumber"));
    }

    private void verifyAssertionAttributes(String authenticationId, Assertion assertion) {
        List<Attribute> attributes = assertion.getAttributeStatements().get(0).getAttributes();
        assertAttributeValue(attributes, "email", "marissa@testing.org");
        assertAttributeValue(attributes, "id", authenticationId);
        assertAttributeValue(attributes, "name", "marissa");
        assertAttributeValue(attributes, "origin", OriginKeys.UAA);
        assertAttributeValue(attributes, "zoneId", "uaa");
    }

    private void assertAttributeDoesNotExist(List<Attribute> attributeList, String name) {
        List<String> matchedAttributes = attributeList.stream()
            .map(Attribute::getName)
            .filter(name::equals)
            .collect(Collectors.toList());
        assertEquals(0, matchedAttributes.size());
    }

    private void assertAttributeValue(List<Attribute> attributeList, String name, String expectedValue) {
        assertAttributeValue(attributeList, name, new String[] {expectedValue});
    }

    private void assertAttributeValue(List<Attribute> attributeList, String name, String... expectedValue) {
        for (Attribute attribute : attributeList) {
            if (attribute.getName().equals(name)) {
                List<XMLObject> xsString = attribute.getAttributeValues();
                List<String> attributeValues = xsString.stream().map(xs -> ((XSString)xs).getValue()).collect(Collectors.toList());
                assertThat(String.format("Attribute mismatch for '%s'.", name), attributeValues, containsInAnyOrder(expectedValue));
                return;
            }
        }

        Assert.fail(String.format("No attribute value with name of '%s'.", name));
    }

    @Test
    public void testBuildResponseWithSignedAssertion() throws SAMLException,
            MetadataProviderException, SecurityException, MarshallingException, SignatureException {
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
