/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.identity.uaa.provider.saml;

import org.apache.xml.security.encryption.XMLCipherParameters;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSQName;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.core.xml.schema.impl.XSBase64BinaryBuilder;
import org.opensaml.core.xml.schema.impl.XSBooleanBuilder;
import org.opensaml.core.xml.schema.impl.XSDateTimeBuilder;
import org.opensaml.core.xml.schema.impl.XSIntegerBuilder;
import org.opensaml.core.xml.schema.impl.XSQNameBuilder;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.core.xml.schema.impl.XSURIBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.namespace.QName;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

/**
 * This class contains functions to create SAML Requests, Responses, Tokens and related objects for testing purposes.
 * These are building blocks, and most of the functionality here can be accessed via Saml2TestUtils, which does additional configuration.
 * <p>
 * This was copied from Spring Security Test Classes
 * Migrate to use the Spring Security class when it is made public
 * <p>
 * Changes:
 * - setValue on interface org.opensaml.core.xml.schema.XSURI
 * - added alot of values to attributeStatements
 */
public final class TestOpenSamlObjects {

    private static final String USERNAME = "test@saml.user";
    private static final String DESTINATION = "http://localhost:8080/uaa/saml/SSO/alias/integration-saml-entity-id";
    private static final String ASSERTING_PARTY_ENTITY_ID = "https://some.idp.test/saml2/idp";
    private static final SecretKey SECRET_KEY = new SecretKeySpec(
            Base64.getDecoder().decode("shOnwNMoCv88HKMEa91+FlYoD5RNvzMTAL5LGxZKIFk="), "AES");
    public static final String RELYING_PARTY_ENTITY_ID = "https://localhost/saml2/service-provider-metadata/idp-alias";

    static {
        OpenSamlInitializationService.initialize();
    }

    private TestOpenSamlObjects() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static Response response() {
        return response(DESTINATION, ASSERTING_PARTY_ENTITY_ID);
    }

    public static Response response(String issuer) {
        return response(DESTINATION, issuer != null ? issuer : ASSERTING_PARTY_ENTITY_ID);
    }

    public static Response response(String destination, String issuerEntityId) {
        Response response = build(Response.DEFAULT_ELEMENT_NAME);
        response.setID("R" + UUID.randomUUID());
        response.setVersion(SAMLVersion.VERSION_20);
        response.setID("_" + UUID.randomUUID());
        response.setDestination(destination);
        response.setIssuer(issuer(issuerEntityId));
        return response;
    }

    static Response signedResponseWithOneAssertion() {
        return signedResponseWithOneAssertion(response -> {
        });
    }

    static Response signedResponseWithOneAssertion(Consumer<Response> responseConsumer) {
        Response response = response();
        response.getAssertions().add(assertion());
        responseConsumer.accept(response);
        return signed(response, TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
    }

    public static Assertion assertion() {
        return assertion(USERNAME, ASSERTING_PARTY_ENTITY_ID, RELYING_PARTY_ENTITY_ID, DESTINATION);
    }

    public static Assertion assertion(String issuer, String username) {
        if (username == null) {
            username = USERNAME;
        }
        if (issuer == null) {
            issuer = ASSERTING_PARTY_ENTITY_ID;
        }
        return assertion(username, issuer, RELYING_PARTY_ENTITY_ID, DESTINATION);
    }

    public static Assertion assertion(String username, String issuerEntityId, String recipientEntityId, String recipientUri) {
        Assertion assertion = build(Assertion.DEFAULT_ELEMENT_NAME);
        assertion.setID("A" + UUID.randomUUID());
        assertion.setVersion(SAMLVersion.VERSION_20);
        assertion.setIssuer(issuer(issuerEntityId));
        assertion.setSubject(subject(username));
        assertion.setConditions(conditions());
        SubjectConfirmation subjectConfirmation = subjectConfirmation();
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData confirmationData = subjectConfirmationData(recipientEntityId);
        confirmationData.setRecipient(recipientUri);
        subjectConfirmation.setSubjectConfirmationData(confirmationData);
        assertion.getSubject().getSubjectConfirmations().add(subjectConfirmation);
        AuthnStatement statement = build(AuthnStatement.DEFAULT_ELEMENT_NAME);
        statement.setSessionIndex("session-index");
        assertion.getAuthnStatements().add(statement);
        return assertion;
    }

    static Issuer issuer(String entityId) {
        Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(entityId);
        return issuer;
    }

    static Subject subject(String principalName) {
        Subject subject = build(Subject.DEFAULT_ELEMENT_NAME);
        if (principalName != null) {
            subject.setNameID(nameId(principalName));
        }
        return subject;
    }

    static NameID nameId(String principalName) {
        NameID nameId = build(NameID.DEFAULT_ELEMENT_NAME);
        nameId.setValue(principalName);
        return nameId;
    }

    static SubjectConfirmation subjectConfirmation() {
        return build(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
    }

    static SubjectConfirmationData subjectConfirmationData(String recipient) {
        SubjectConfirmationData subject = build(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
        subject.setRecipient(recipient);
        return subject;
    }

    static Conditions conditions() {
        return build(Conditions.DEFAULT_ELEMENT_NAME);
    }

    public static AuthnRequest authnRequest() {
        Issuer issuer = build(Issuer.DEFAULT_ELEMENT_NAME);
        issuer.setValue(ASSERTING_PARTY_ENTITY_ID);
        AuthnRequest authnRequest = build(AuthnRequest.DEFAULT_ELEMENT_NAME);
        authnRequest.setIssuer(issuer);
        authnRequest.setDestination(ASSERTING_PARTY_ENTITY_ID + "/SSO.saml2");
        authnRequest.setAssertionConsumerServiceURL(DESTINATION);
        return authnRequest;
    }

    static Credential getSigningCredential(Saml2X509Credential credential, String entityId) {
        BasicCredential cred = getBasicCredential(credential);
        cred.setEntityId(entityId);
        cred.setUsageType(UsageType.SIGNING);
        return cred;
    }

    static BasicCredential getBasicCredential(Saml2X509Credential credential) {
        return CredentialSupport.getSimpleCredential(credential.getCertificate(), credential.getPrivateKey());
    }

    static <T extends SignableSAMLObject> T signed(T signable, Saml2X509Credential credential, String entityId,
            String signAlgorithmUri) {
        SignatureSigningParameters parameters = new SignatureSigningParameters();
        Credential signingCredential = getSigningCredential(credential, entityId);
        parameters.setSigningCredential(signingCredential);
        parameters.setSignatureAlgorithm(signAlgorithmUri);
        parameters.setSignatureReferenceDigestMethod(SignatureConstants.ALGO_ID_DIGEST_SHA256);
        parameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
        x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);
        parameters.setKeyInfoGenerator(x509KeyInfoGeneratorFactory.newInstance());
        try {
            SignatureSupport.signObject(signable, parameters);
        } catch (MarshallingException | SignatureException | SecurityException ex) {
            throw new Saml2Exception(ex);
        }
        return signable;
    }

    public static <T extends SignableSAMLObject> T signed(T signable, Saml2X509Credential credential, String entityId) {
        return signed(signable, credential, entityId, SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
    }

    static EncryptedAssertion encrypted(Assertion assertion, Saml2X509Credential credential) {
        X509Certificate certificate = credential.getCertificate();
        Encrypter encrypter = getEncrypter(certificate);
        try {
            return encrypter.encrypt(assertion);
        } catch (EncryptionException ex) {
            throw new Saml2Exception("Unable to encrypt assertion.", ex);
        }
    }

    static EncryptedID encrypted(NameID nameId, Saml2X509Credential credential) {
        X509Certificate certificate = credential.getCertificate();
        Encrypter encrypter = getEncrypter(certificate);
        try {
            return encrypter.encrypt(nameId);
        } catch (EncryptionException ex) {
            throw new Saml2Exception("Unable to encrypt nameID.", ex);
        }
    }

    static EncryptedAttribute encrypted(String name, String value, Saml2X509Credential credential) {
        Attribute attribute = attribute(name, value);
        X509Certificate certificate = credential.getCertificate();
        Encrypter encrypter = getEncrypter(certificate);
        try {
            return encrypter.encrypt(attribute);
        } catch (EncryptionException ex) {
            throw new Saml2Exception("Unable to encrypt nameID.", ex);
        }
    }

    private static Encrypter getEncrypter(X509Certificate certificate) {
        String dataAlgorithm = XMLCipherParameters.AES_256;
        String keyAlgorithm = XMLCipherParameters.RSA_1_5;
        BasicCredential dataCredential = new BasicCredential(SECRET_KEY);
        DataEncryptionParameters dataEncryptionParameters = new DataEncryptionParameters();
        dataEncryptionParameters.setEncryptionCredential(dataCredential);
        dataEncryptionParameters.setAlgorithm(dataAlgorithm);
        Credential credential = CredentialSupport.getSimpleCredential(certificate, null);
        KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
        keyEncryptionParameters.setEncryptionCredential(credential);
        keyEncryptionParameters.setAlgorithm(keyAlgorithm);
        Encrypter encrypter = new Encrypter(dataEncryptionParameters, keyEncryptionParameters);
        Encrypter.KeyPlacement keyPlacement = Encrypter.KeyPlacement.valueOf("PEER");
        encrypter.setKeyPlacement(keyPlacement);
        return encrypter;
    }

    static Attribute attribute(String name, String value) {
        Attribute attribute = build(Attribute.DEFAULT_ELEMENT_NAME);
        attribute.setName(name);
        XSString xsValue = new XSStringBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        xsValue.setValue(value);
        attribute.getAttributeValues().add(xsValue);
        return attribute;
    }

    static AttributeStatement customAttributeStatement(String attributeName, XMLObject customAttributeValue) {
        AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
        AttributeBuilder attributeBuilder = new AttributeBuilder();
        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(attributeName);
        attribute.getAttributeValues().add(customAttributeValue);
        AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
        attributeStatement.getAttributes().add(attribute);
        return attributeStatement;
    }

    public static List<AttributeStatement> attributeStatements(Map<String, String> attributeMap) {
        Attribute[] attributes = attributeMap.entrySet().stream()
                .map(entry -> attributeWithStringValue(entry.getKey(), entry.getValue()))
                .toArray(Attribute[]::new);

        return List.of(attributeStatement(attributes));
    }

    public static List<AttributeStatement> attributeStatements() {
        List<AttributeStatement> attributeStatements = new ArrayList<>();

        attributeStatements.add(attributeStatement(
                attributeWithAnyValues("email", "john.doe@example.com", "doe.john@example.com"),
                attributeWithAnyValues("secondaryEmail", "john.doe.secondary@example.com"),
                attributeWithStringValue("name", "John Doe"),
                attributeWithStringValue("firstName", "John"),
                attributeWithStringValue("lastName", "Doe"),
                attributeWithStringValue("role", "RoleOne"),
                attributeWithStringValue("role", "RoleTwo"),
                attributeWithIntValue("age", 21),
                attributeWithStringValue("phone", "123-456-7890"),
                attributeWithAnyValues("manager", "John the Sloth", "Kari the Ant Eater"),
                attributeWithAnyValues("costCenter", "Denver,CO")
        ));

        attributeStatements.add(attributeStatement(
                attributeWithUriValue("website", "https://johndoe.com/"),
                attributeWithBooleanValue("registered", true),
                attributeWithStringValue("acr", AuthnContext.PASSWORD_AUTHN_CTX),
                attributeWithAnyValues("groups", "saml.admin", "saml.user", "saml.unmapped"),
                attributeWithAnyValues("2ndgroups", "saml.test"),
                // Ensure an empty attribute is handled properly
                attributeWithNoValue(),
                // Ensure an empty attribute value is handled properly
                attributeWithNullValue()
        ));

        // Ensure an empty attribute statement is handled properly
        attributeStatements.add(attributeStatement());

        attributeStatements.add(attributeStatement(
                attributeWithUriValue("XSURI", "http://localhost:8080/someuri"),
                attributeWithAnyValues("XSAny", "XSAnyValue"),
                attributeWithQNameValue("XSQName", "XSQNameValue"),
                attributeWithIntValue("XSInteger", 3),
                attributeWithBooleanValue("XSBoolean", true),
                attributeWithDateTimeValue("XSDateTime", Instant.ofEpochSecond(0)),
                attributeWithBase64BinaryValue("XSBase64Binary", "00001111")
        ));

        return attributeStatements;
    }

    private static AttributeStatement attributeStatement(Attribute... attributes) {
        AttributeStatement attrStmt = new AttributeStatementBuilder().buildObject();
        attrStmt.getAttributes().addAll(Arrays.asList(attributes));
        return attrStmt;
    }

    /**
     * Attribute with a null value
     */
    private static Attribute attributeWithNullValue() {
        Attribute attr = new AttributeBuilder().buildObject();
        attr.setName("emptyAttributeValue");
        attr.getAttributeValues().add(null);

        return attr;
    }

    /**
     * Attribute with no values
     */
    private static Attribute attributeWithNoValue() {
        Attribute attr = new AttributeBuilder().buildObject();
        attr.setName("emptyAttribute");

        return attr;
    }

    private static Attribute attributeWithAnyValues(String attributeName, String... attribValues) {
        Attribute attr = new AttributeBuilder().buildObject();
        attr.setName(attributeName);

        for (String attribValue : attribValues) {
            XSAny value = new XSAnyBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSAny.TYPE_NAME);
            value.setTextContent(attribValue);
            attr.getAttributeValues().add(value);
        }
        return attr;
    }

    private static Attribute attributeWithStringValue(String attributeName, String attribValue) {
        Attribute attr = new AttributeBuilder().buildObject();
        attr.setName(attributeName);
        XSString value = new XSStringBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        value.setValue(attribValue);
        attr.getAttributeValues().add(value);

        return attr;
    }

    private static Attribute attributeWithBooleanValue(String attributeName, boolean attribValue) {
        Attribute attr = new AttributeBuilder().buildObject();
        attr.setName(attributeName);
        XSBoolean value = new XSBooleanBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSBoolean.TYPE_NAME);
        value.setValue(new XSBooleanValue(attribValue, false));
        attr.getAttributeValues().add(value);

        return attr;
    }

    private static Attribute attributeWithUriValue(String attributeName, String attribValue) {
        Attribute attr = new AttributeBuilder().buildObject();
        attr.setName(attributeName);
        XSURI value = new XSURIBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSURI.TYPE_NAME);
        value.setURI(attribValue);
        attr.getAttributeValues().add(value);

        return attr;
    }

    private static Attribute attributeWithIntValue(String attributeName, int attribValue) {
        Attribute attr = new AttributeBuilder().buildObject();
        attr.setName(attributeName);
        XSInteger value = new XSIntegerBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSInteger.TYPE_NAME);
        value.setValue(attribValue);
        attr.getAttributeValues().add(value);

        return attr;
    }

    private static Attribute attributeWithQNameValue(String attributeName, String attribValue) {
        Attribute attr = new AttributeBuilder().buildObject();
        attr.setName(attributeName);
        XSQName value = new XSQNameBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSQName.TYPE_NAME);
        value.setValue(QName.valueOf(attribValue));
        attr.getAttributeValues().add(value);

        return attr;
    }

    private static Attribute attributeWithBase64BinaryValue(String attributeName, String attribValue) {
        Attribute attr = new AttributeBuilder().buildObject();
        attr.setName(attributeName);
        XSBase64Binary value = new XSBase64BinaryBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSBase64Binary.TYPE_NAME);
        value.setValue(attribValue);
        attr.getAttributeValues().add(value);

        return attr;
    }

    private static Attribute attributeWithDateTimeValue(String attributeName, Instant attribValue) {
        Attribute attr = new AttributeBuilder().buildObject();
        attr.setName(attributeName);
        XSDateTime value = new XSDateTimeBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSDateTime.TYPE_NAME);
        value.setValue(attribValue);
        attr.getAttributeValues().add(value);

        return attr;
    }

    static Status successStatus() {
        return status(StatusCode.SUCCESS);
    }

    static Status status(String code) {
        Status status = new StatusBuilder().buildObject();
        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue(code);
        status.setStatusCode(statusCode);
        return status;
    }

    public static LogoutRequest assertingPartyLogoutRequest(RelyingPartyRegistration registration) {
        LogoutRequestBuilder logoutRequestBuilder = new LogoutRequestBuilder();
        LogoutRequest logoutRequest = logoutRequestBuilder.buildObject();
        logoutRequest.setID("id");
        NameIDBuilder nameIdBuilder = new NameIDBuilder();
        NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue("user");
        logoutRequest.setNameID(nameId);
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(registration.getAssertingPartyDetails().getEntityId());
        logoutRequest.setIssuer(issuer);
        logoutRequest.setDestination(registration.getSingleLogoutServiceLocation());
        return logoutRequest;
    }

    public static LogoutRequest assertingPartyLogoutRequestNameIdInEncryptedId(RelyingPartyRegistration registration) {
        LogoutRequestBuilder logoutRequestBuilder = new LogoutRequestBuilder();
        LogoutRequest logoutRequest = logoutRequestBuilder.buildObject();
        logoutRequest.setID("id");
        NameIDBuilder nameIdBuilder = new NameIDBuilder();
        NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue("user");
        logoutRequest.setNameID(null);
        Saml2X509Credential credential = registration.getAssertingPartyDetails()
                .getEncryptionX509Credentials()
                .iterator()
                .next();
        EncryptedID encrypted = encrypted(nameId, credential);
        logoutRequest.setEncryptedID(encrypted);
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(registration.getAssertingPartyDetails().getEntityId());
        logoutRequest.setIssuer(issuer);
        logoutRequest.setDestination(registration.getSingleLogoutServiceLocation());
        return logoutRequest;
    }

    public static LogoutResponse assertingPartyLogoutResponse(RelyingPartyRegistration registration) {
        LogoutResponseBuilder logoutResponseBuilder = new LogoutResponseBuilder();
        LogoutResponse logoutResponse = logoutResponseBuilder.buildObject();
        logoutResponse.setID("id");
        StatusBuilder statusBuilder = new StatusBuilder();
        StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
        StatusCode code = statusCodeBuilder.buildObject();
        code.setValue(StatusCode.SUCCESS);
        Status status = statusBuilder.buildObject();
        status.setStatusCode(code);
        logoutResponse.setStatus(status);
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(registration.getAssertingPartyDetails().getEntityId());
        logoutResponse.setIssuer(issuer);
        logoutResponse.setDestination(registration.getSingleLogoutServiceResponseLocation());
        return logoutResponse;
    }

    public static LogoutRequest relyingPartyLogoutRequest(RelyingPartyRegistration registration) {
        LogoutRequestBuilder logoutRequestBuilder = new LogoutRequestBuilder();
        LogoutRequest logoutRequest = logoutRequestBuilder.buildObject();
        logoutRequest.setID("id");
        NameIDBuilder nameIdBuilder = new NameIDBuilder();
        NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue("user");
        logoutRequest.setNameID(nameId);
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(registration.getAssertingPartyDetails().getEntityId());
        logoutRequest.setIssuer(issuer);
        logoutRequest.setDestination(registration.getAssertingPartyDetails().getSingleLogoutServiceLocation());
        return logoutRequest;
    }

    static <T extends XMLObject> T build(QName qName) {
        return (T) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(qName).buildObject(qName);
    }

    public static String getEncodedAssertion(String issuerEntityId,
            String format, String username,
            String spEndpoint, String audienceEntityID, boolean sign) {
        final Instant now = Instant.now();
        final Instant until = now.plus(1, java.time.temporal.ChronoUnit.HOURS);

        Assertion assertion = assertion(username, issuerEntityId, audienceEntityID, spEndpoint);
        assertion.setIssueInstant(now);

        // update subject
        assertion.getSubject().getNameID().setNameQualifier(NameID.UNSPECIFIED);
        assertion.getSubject().getNameID().setFormat(format);
        assertion.getSubject().getSubjectConfirmations().getFirst().getSubjectConfirmationData().setNotOnOrAfter(until);

        // update conditions
        final Audience audience = build(Audience.DEFAULT_ELEMENT_NAME);
        audience.setURI(audienceEntityID);
        final AudienceRestriction audienceRestriction = build(AudienceRestriction.DEFAULT_ELEMENT_NAME);
        audienceRestriction.getAudiences().add(audience);

        assertion.getConditions().setNotBefore(now.minusSeconds(2));
        assertion.getConditions().setNotOnOrAfter(until);
        assertion.getConditions().getAudienceRestrictions().add(audienceRestriction);

        // update authn statement
        final AuthnContextClassRef authnContextClassRef = build(AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
        authnContextClassRef.setURI("urn:oasis:names:tc:SAML:2.0:ac:classes:Password");
        final AuthnContext authnContext = build(AuthnContext.DEFAULT_ELEMENT_NAME);
        authnContext.setAuthnContextClassRef(authnContextClassRef);

        final AuthnStatement authnStatement = assertion.getAuthnStatements().getFirst();
        authnStatement.setAuthnInstant(now);
        authnStatement.setSessionIndex("a358a06c15ja8d7a1idjaj07jb52gdi");
        authnStatement.setSessionNotOnOrAfter(until);
        authnStatement.setAuthnContext(authnContext);

        // sign, serialize and encode
        if (sign) {
            Saml2X509Credential signingCredential = Saml2X509Credential.signing(TestCredentialObjects.legacyPrivateKey(), TestCredentialObjects.legacyX509Certificate());
            assertion = signed(assertion, signingCredential, issuerEntityId);
        }
        String serialized = Saml2TestUtils.serialize(assertion);
        return Saml2Utils.samlBearerEncode(serialized);
    }
}
