package org.cloudfoundry.identity.uaa.provider.saml.idp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.SAMLException;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
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
    public void testBuildResponse() throws MessageEncodingException, SAMLException, MetadataProviderException,
            SecurityException, MarshallingException, SignatureException {
        IdpWebSsoProfileImpl profile = new IdpWebSsoProfileImpl();

        Authentication authentication = samlTestUtils.mockAuthentication();
        SAMLMessageContext context = samlTestUtils.mockSamlMessageContext();

        IdpWebSSOProfileOptions options = new IdpWebSSOProfileOptions();
        options.setAssertionsSigned(false);
        profile.buildResponse(authentication, context, options);

        AuthnRequest request = (AuthnRequest) context.getInboundSAMLMessage();
        Response response = (Response) context.getOutboundSAMLMessage();
        Assertion assertion = response.getAssertions().get(0);
        Subject subject = assertion.getSubject();
        assertEquals("marissa", subject.getNameID().getValue());

        SubjectConfirmation subjectConfirmation = subject.getSubjectConfirmations().get(0);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmation.getSubjectConfirmationData();
        assertEquals(request.getID(), subjectConfirmationData.getInResponseTo());
    }

    @Test
    public void testBuildResponseWithSignedAssertion() throws MessageEncodingException, SAMLException,
            MetadataProviderException, SecurityException, MarshallingException, SignatureException {
        IdpWebSsoProfileImpl profile = new IdpWebSsoProfileImpl();

        Authentication authentication = samlTestUtils.mockAuthentication();
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

        assertNotNull(assertion.getSignature());
    }

}
