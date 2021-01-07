/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml.idp;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
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
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Optional.ofNullable;


public class IdpWebSsoProfileImpl extends WebSSOProfileImpl implements IdpWebSsoProfile {

    private JdbcSamlServiceProviderProvisioning samlServiceProviderProvisioning;
    private JdbcScimUserProvisioning scimUserProvisioning;

    @Override
    public void sendResponse(Authentication authentication, SAMLMessageContext context, IdpWebSSOProfileOptions options)
            throws SAMLException, MetadataProviderException, MessageEncodingException, SecurityException,
            MarshallingException, SignatureException {

        buildResponse(authentication, context, options);

        sendMessage(context, false);
    }

    public AuthnRequest buildIdpInitiatedAuthnRequest(String nameIDFormat,
                                                      String spEntityID,
                                                      String assertionUrl) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<AuthnRequest> builder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
            .getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
        AuthnRequest request = builder.buildObject();
        request.setVersion(SAMLVersion.VERSION_20);
        request.setID(generateID());
        request.setIssuer(getIssuer(spEntityID));
        request.setVersion(SAMLVersion.VERSION_20);
        request.setIssueInstant(new DateTime());
        request.setID(null);
        request.setAssertionConsumerServiceURL(assertionUrl);
        if (null != nameIDFormat) {
            NameID nameID = ((SAMLObjectBuilder<NameID>) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME)).buildObject();
            nameID.setFormat(nameIDFormat);
            Subject subject = ((SAMLObjectBuilder<Subject>) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME)).buildObject();
            subject.setNameID(nameID);
            request.setSubject(subject);
        }
        return request;
    }

    @SuppressWarnings("unchecked")
    protected void buildResponse(Authentication authentication, SAMLMessageContext context,
            IdpWebSSOProfileOptions options)
                    throws MetadataProviderException, SecurityException, MarshallingException, SignatureException,
            SAMLException {
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
        Response samlResponse = createResponse(context, assertionConsumerService, assertion, authnRequest);
        context.setOutboundMessage(samlResponse);
        context.setOutboundSAMLMessage(samlResponse);
    }

    private Response createResponse(SAMLMessageContext context, AssertionConsumerService assertionConsumerService,
            Assertion assertion, AuthnRequest authnRequest) {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) builderFactory
                .getBuilder(Response.DEFAULT_ELEMENT_NAME);
        Response response = responseBuilder.buildObject();

        buildCommonAttributes(context.getLocalEntityId(), response, assertionConsumerService, authnRequest);

        response.getAssertions().add(assertion);

        buildStatusSuccess(response);
        return response;
    }

    private void buildCommonAttributes(String localEntityId, Response response, Endpoint service,
                                       AuthnRequest authnRequest) {

        response.setID(generateID());
        response.setIssuer(getIssuer(localEntityId));
        response.setInResponseTo(authnRequest.getID());
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssueInstant(new DateTime());

        if (service != null) {
            response.setDestination(service.getLocation());
        }
    }

    private Assertion buildAssertion(Authentication authentication, AuthnRequest authnRequest,
            IdpWebSSOProfileOptions options, String audienceURI, String issuerEntityId) throws SAMLException{
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
                (UaaPrincipal) authentication.getPrincipal());
        buildAttributeStatement(assertion, authentication, audienceURI);

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
            UaaPrincipal uaaPrincipal) throws SAMLException {
        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) builderFactory
                .getBuilder(Subject.DEFAULT_ELEMENT_NAME);
        Subject subject = subjectBuilder.buildObject();

        @SuppressWarnings("unchecked")
        SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) builderFactory
                .getBuilder(NameID.DEFAULT_ELEMENT_NAME);
        NameID nameID = nameIdBuilder.buildObject();

        String nameIDFormat = NameIDType.UNSPECIFIED;
        String nameIdStr = uaaPrincipal.getName();
        if(null != authnRequest.getSubject() && null != authnRequest.getSubject().getNameID()
                && null != authnRequest.getSubject().getNameID().getFormat()){

            nameIDFormat = authnRequest.getSubject().getNameID().getFormat();
            switch (nameIDFormat) {
                case NameIDType.EMAIL:
                    nameIdStr = uaaPrincipal.getEmail();
                    break;
                case NameIDType.PERSISTENT:
                    nameIdStr = uaaPrincipal.getId();
                    break;
                case NameIDType.UNSPECIFIED:
                    nameIdStr = uaaPrincipal.getName();
                    break;
                default:
                    throw new SAMLException("The NameIDType '" + nameIDFormat + "' is not supported.");
            }
        }

        nameID.setValue(nameIdStr);
        nameID.setFormat(nameIDFormat);
        subject.setNameID(nameID);

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

    protected void buildAttributeStatement(Assertion assertion, Authentication authentication, String providerEntityId) {
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
        Attribute emailAttribute = buildStringAttribute("email", Collections.singletonList(principal.getEmail()));
        attributeStatement.getAttributes().add(emailAttribute);
        Attribute idAttribute = buildStringAttribute("id", Collections.singletonList(principal.getId()));
        attributeStatement.getAttributes().add(idAttribute);
        Attribute nameAttribute = buildStringAttribute("name", Collections.singletonList(principal.getName()));
        attributeStatement.getAttributes().add(nameAttribute);
        Attribute originAttribute = buildStringAttribute("origin", Collections.singletonList(principal.getOrigin()));
        attributeStatement.getAttributes().add(originAttribute);
        Attribute zoneAttribute = buildStringAttribute("zoneId", Collections.singletonList(principal.getZoneId()));
        attributeStatement.getAttributes().add(zoneAttribute);

        SamlServiceProviderDefinition config = samlServiceProviderProvisioning.retrieveByEntityId(providerEntityId, IdentityZoneHolder.get().getId()).getConfig();

        //static attributes
        for (Map.Entry<String,Object> staticAttribute : (ofNullable(config.getStaticCustomAttributes()).orElse(Collections.emptyMap())).entrySet()) {
            String name = staticAttribute.getKey();
            Object value = staticAttribute.getValue();
            if (value==null) {
                continue;
            }

            List values = new LinkedList<>();
            if (value instanceof List) {
                values = (List) value;
            } else {
                values.add(value);
            }

            List<String> stringValues = (List) values.stream().map(s -> s==null ? "null" : s.toString()).collect(Collectors.toList());
            attributeStatement.getAttributes().add(buildStringAttribute(name, stringValues));
        }

        Map<String, Object> attributeMappings = config.getAttributeMappings();

        ScimUser user = scimUserProvisioning.retrieve(principal.getId(), IdentityZoneHolder.get().getId());

        if(user.getCustomAttributes() != null) {
            for(Map.Entry<String, String> entry : user.getCustomAttributes().entrySet()) {
                String attributeName = entry.getKey();
                String attributeValue = entry.getValue();
                if(StringUtils.hasText(attributeName) && StringUtils.hasText(attributeValue)) {
                    Attribute customAttribute = buildStringAttribute(attributeName,
                            Collections.singletonList(attributeValue));
                    attributeStatement.getAttributes().add(customAttribute);
                }
            }
        }
        if (attributeMappings.size() > 0) {

            String givenName = user.getGivenName();
            if (StringUtils.hasText(givenName) && attributeMappings.containsKey("given_name")) {
                Attribute givenNameAttribute = buildStringAttribute(attributeMappings.get("given_name").toString(), Collections.singletonList(givenName));
                attributeStatement.getAttributes().add(givenNameAttribute);
            }

            String familyName = user.getFamilyName();
            if (StringUtils.hasText(familyName) && attributeMappings.containsKey("family_name")) {
                Attribute familyNameAttribute = buildStringAttribute(attributeMappings.get("family_name").toString(), Collections.singletonList(familyName));
                attributeStatement.getAttributes().add(familyNameAttribute);
            }

            String phoneNumber = scimUserProvisioning.extractPhoneNumber(user);
            if (StringUtils.hasText(phoneNumber) && attributeMappings.containsKey("phone_number")) {
                Attribute phoneNumberAttribute = buildStringAttribute(attributeMappings.get("phone_number").toString(), Collections.singletonList(phoneNumber));
                attributeStatement.getAttributes().add(phoneNumberAttribute);
            }

            String email = user.getPrimaryEmail();
            if (StringUtils.hasText(email) && attributeMappings.containsKey("email")) {
                Attribute customEmailAttribute = buildStringAttribute(attributeMappings.get("email").toString(), Collections.singletonList(email));
                attributeStatement.getAttributes().add(customEmailAttribute);
            }
        }

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

    public void setSamlServiceProviderProvisioning(JdbcSamlServiceProviderProvisioning samlServiceProviderProvisioning) {
        this.samlServiceProviderProvisioning = samlServiceProviderProvisioning;
    }

    public void setScimUserProvisioning(JdbcScimUserProvisioning scimUserProvisioning) {
        this.scimUserProvisioning = scimUserProvisioning;
    }
}
