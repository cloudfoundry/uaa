package org.cloudfoundry.identity.uaa.provider.saml.idp;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.websso.WebSSOProfileImpl;

public class IdpWebSsoProfileImpl extends WebSSOProfileImpl implements IdpWebSsoProfile {

    @Override
    public void sendResponse(Authentication authentication, SAMLMessageContext context, IdpWebSSOProfileOptions options)
            throws SAMLException, MetadataProviderException, MessageEncodingException, SecurityException,
            MarshallingException, SignatureException {

        buildResponse(authentication, context, options);

        sendMessage(context, false);
    }

    @SuppressWarnings("unchecked")
    protected void buildResponse(Authentication authentication, SAMLMessageContext context,
            IdpWebSSOProfileOptions options)
                    throws MetadataProviderException, SecurityException, MarshallingException, SignatureException {
        IDPSSODescriptor idpDescriptor = (IDPSSODescriptor) context.getLocalEntityRoleMetadata();
        SPSSODescriptor spDescriptor = (SPSSODescriptor) context.getPeerEntityRoleMetadata();
        AuthnRequest authnRequest = (AuthnRequest) context.getInboundSAMLMessage();

        AssertionConsumerService assertionConsumerService = getAssertionConsumerService(options, idpDescriptor,
                spDescriptor);

        context.setPeerEntityEndpoint(assertionConsumerService);

        Assertion assertion = buildAssertion(authentication, authnRequest, options, context.getPeerEntityId(),
                context.getLocalEntityId());
        if (options.isAssertionsSigned() || spDescriptor.getWantAssertionsSigned()) {
            signAssertion(assertion, context.getLocalSigningCredential());
        }
        Response samlResponse = createResponse(context, assertionConsumerService, assertion);
        context.setOutboundMessage(samlResponse);
        context.setOutboundSAMLMessage(samlResponse);
    }

    private Response createResponse(SAMLMessageContext context, AssertionConsumerService assertionConsumerService,
            Assertion assertion) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory
                .getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response response = responseBuilder.buildObject();

        buildCommonAttributes(context.getLocalEntityId(), response, assertionConsumerService);

        response.getAssertions().add(assertion);

        buildStatusSuccess(response);
        return response;
    }

    private void buildCommonAttributes(String localEntityId, Response response, Endpoint service) {

        response.setID(generateID());
        response.setIssuer(getIssuer(localEntityId));
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssueInstant(new DateTime());

        if (service != null) {
            response.setDestination(service.getLocation());
        }
    }

    private Assertion buildAssertion(Authentication authentication, AuthnRequest authnRequest,
            IdpWebSSOProfileOptions options, String audienceURI, String issuerEntityId) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) builderFactory
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(generateID());
        assertion.setIssueInstant(new DateTime());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(getIssuer(issuerEntityId));

        buildAssertionAuthnStatement(assertion);
        buildAssertionConditions(assertion, options.getAssertionTimeToLiveSeconds(), audienceURI);
        buildAssertionSubject(assertion, authnRequest, options.getAssertionTimeToLiveSeconds(),
                authentication.getName());
        buildAttributeStatement(assertion, authentication);

        return assertion;
    }

    private void buildAssertionAuthnStatement(Assertion assertion) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AuthnStatement> authnStatementBuilder = (SAMLObjectBuilder<AuthnStatement>) builderFactory
                .getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
        AuthnStatement authnStatement = authnStatementBuilder.buildObject();
        authnStatement.setAuthnInstant(new DateTime());
        authnStatement.setSessionIndex(generateID());

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AuthnContext> authnContextBuilder = (SAMLObjectBuilder<AuthnContext>) builderFactory
                .getBuilder(AuthnContext.DEFAULT_ELEMENT_NAME);
        AuthnContext authnContext = authnContextBuilder.buildObject();

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AuthnContextClassRef> authnContextClassRefBuilder = (SAMLObjectBuilder<AuthnContextClassRef>) builderFactory
                .getBuilder(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject();
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);
        assertion.getAuthnStatements().add(authnStatement);
    }

    private void buildAssertionConditions(Assertion assertion, int assertionTtlSeconds, String audienceURI) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Conditions> conditionsBuilder = (SAMLObjectBuilder<Conditions>) builderFactory
                .getBuilder(Conditions.DEFAULT_ELEMENT_NAME);
        Conditions conditions = conditionsBuilder.buildObject();
        conditions.setNotBefore(new DateTime());
        conditions.setNotOnOrAfter(new DateTime().plusSeconds(assertionTtlSeconds));

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AudienceRestriction> audienceRestrictionBuilder = (SAMLObjectBuilder<AudienceRestriction>) builderFactory
                .getBuilder(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        AudienceRestriction audienceRestriction = audienceRestrictionBuilder.buildObject();

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Audience> audienceBuilder = (SAMLObjectBuilder<Audience>) builderFactory
                .getBuilder(Audience.DEFAULT_ELEMENT_NAME);
        Audience audience = audienceBuilder.buildObject();
        audience.setAudienceURI(audienceURI);
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        assertion.setConditions(conditions);
    }

    private void buildAssertionSubject(Assertion assertion, AuthnRequest authnRequest, int assertionTtlSeconds,
            String nameIdStr) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) builderFactory
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue(nameIdStr);
        nameId.setFormat(NameIDType.UNSPECIFIED);
        subject.setNameID(nameId);

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<SubjectConfirmation> subjectConfirmationBuilder = (SAMLObjectBuilder<SubjectConfirmation>) builderFactory
                .getBuilder(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<SubjectConfirmationData> subjectConfirmationDataBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) builderFactory
                .getBuilder(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        SubjectConfirmationData subjectConfirmationData = subjectConfirmationDataBuilder.buildObject();

        subjectConfirmationData.setNotOnOrAfter(new DateTime().plusSeconds(assertionTtlSeconds));
        subjectConfirmationData.setInResponseTo(authnRequest.getID());
        subjectConfirmationData.setRecipient(authnRequest.getAssertionConsumerServiceURL());
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        assertion.setSubject(subject);
    }

    private void buildAttributeStatement(Assertion assertion, Authentication authentication) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AttributeStatement> attributeStatementBuilder = (SAMLObjectBuilder<AttributeStatement>) builderFactory
                .getBuilder(AttributeStatement.DEFAULT_ELEMENT_NAME);
        AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();

        List<String> authorities = new ArrayList<>();
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            authorities.add(authority.getAuthority());
        }
        Attribute authoritiesAttribute = buildStringAttribute("authorities", authorities);
        attributeStatement.getAttributes().add(authoritiesAttribute);

        UaaPrincipal principal = (UaaPrincipal) authentication.getPrincipal();
        Attribute emailAttribute = buildStringAttribute("email", Arrays.asList(new String[] { principal.getEmail() }));
        attributeStatement.getAttributes().add(emailAttribute);
        Attribute idAttribute = buildStringAttribute("email", Arrays.asList(new String[] { principal.getId() }));
        attributeStatement.getAttributes().add(idAttribute);
        Attribute nameAttribute = buildStringAttribute("name", Arrays.asList(new String[] { principal.getName() }));
        attributeStatement.getAttributes().add(nameAttribute);
        Attribute originAttribute = buildStringAttribute("name", Arrays.asList(new String[] { principal.getOrigin() }));
        attributeStatement.getAttributes().add(originAttribute);
        Attribute zoneAttribute = buildStringAttribute("name", Arrays.asList(new String[] { principal.getZoneId() }));
        attributeStatement.getAttributes().add(zoneAttribute);

        assertion.getAttributeStatements().add(attributeStatement);
    }

    public Attribute buildStringAttribute(String name, List<String> values) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Attribute> attributeBuilder = (SAMLObjectBuilder<Attribute>) builderFactory
                .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);
        Attribute attribute = (Attribute) attributeBuilder.buildObject();
        attribute.setName(name);

        @SuppressWarnings("unchecked")
        XMLObjectBuilder<XSString> xsStringBuilder = (XMLObjectBuilder<XSString>) builderFactory
                .getBuilder(XSString.TYPE_NAME);
        for (String value : values) {
            // Set custom Attributes
            XSString attributeValue = xsStringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                    XSString.TYPE_NAME);
            attributeValue.setValue(value);
            attribute.getAttributeValues().add(attributeValue);
        }

        return attribute;
    }

    private void buildStatusSuccess(Response response) {
        buildStatus(response, StatusCode.SUCCESS_URI);
    }

    private void buildStatus(Response response, String statusCodeStr) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<StatusCode> statusCodeBuilder = (SAMLObjectBuilder<StatusCode>) builderFactory
                .getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(statusCodeStr);

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Status> statusBuilder = (SAMLObjectBuilder<Status>) builderFactory
                .getBuilder(Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);
        response.setStatus(status);
    }

    private void signAssertion(Assertion assertion, Credential credential)
            throws SecurityException, MarshallingException, SignatureException {
        SignatureBuilder signatureBuilder = (SignatureBuilder) builderFactory
                .getBuilder(Signature.DEFAULT_ELEMENT_NAME);
        Signature signature = signatureBuilder.buildObject();
        signature.setSigningCredential(credential);

        SecurityHelper.prepareSignatureParams(signature, credential, null, null);
        assertion.setSignature(signature);

        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(assertion);
        marshaller.marshall(assertion);

        Signer.signObject(signature);
    }

}
