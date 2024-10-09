/*
 * Copyright 2002-2021 the original author or authors.
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

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.impl.XSDateTimeBuilder;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * This class contains functions to create SAML Requests, Responses, Tokens and related objects for testing purposes.
 *
 * @see TestOpenSamlObjects
 * <p>
 * The Functions in here were copied from Spring-Security Test Classes and made static:
 * - spring-security/saml2/saml2-service-provider/src/opensaml4Test/java/org/springframework/security/saml2/provider/service/authentication/OpenSaml4AuthenticationProviderTests
 */
public final class Saml2TestUtils {

    private static final String DESTINATION = "http://localhost:8080/uaa/saml/SSO/alias/integration-saml-entity-id";

    private static final String RELYING_PARTY_ENTITY_ID = "https://localhost/saml2/service-provider-metadata/idp-alias";

    private static final String ASSERTING_PARTY_ENTITY_ID = "https://some.idp.test/saml2/idp";

    private Saml2TestUtils() {
        throw new java.lang.UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static Saml2AuthenticationToken authenticationToken() {
        return authenticationToken(null, attributeStatements(TestOpenSamlObjects.attributeStatements()));
    }

    public static Saml2AuthenticationToken authenticationToken(String username, List<AttributeStatement> attributeStatements) {
        Response response = responseWithAssertions(username, attributeStatements);

        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, false);
        return token(response, verifying(registration()), mockAuthenticationRequest);
    }

    public static Response responseWithAssertions() {
        return responseWithAssertions(null, TestOpenSamlObjects.attributeStatements());
    }

    public static Response responseWithAssertions(String username, List<AttributeStatement> attributeStatements) {
        Response response = response();
        Assertion assertion = assertion(username, null);
        assertion.getAttributeStatements().addAll(attributeStatements);

        Assertion signedAssertion = TestOpenSamlObjects.signed(assertion,
                TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID,
                SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);

        response.getAssertions().add(signedAssertion);

        return response;
    }

    public static String serialize(XMLObject object) {
        try {
            Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
            Element element = marshaller.marshall(object);
            return SerializeSupport.nodeToString(element);
        } catch (MarshallingException ex) {
            throw new Saml2Exception(ex);
        }
    }

    public static Response response() {
        Response response = TestOpenSamlObjects.response();
        response.setIssueInstant(Instant.now());
        return response;
    }

    private static AuthnRequest request() {
        return TestOpenSamlObjects.authnRequest();
    }

    private static String serializedRequest(AuthnRequest request, Saml2MessageBinding binding) {
        String xml = serialize(request);
        return (binding == Saml2MessageBinding.POST) ? Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8))
                : Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
    }

    public static String serializedResponse(Response response) {
        String xml = serialize(response);
        return Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8));
    }

    private static Assertion assertion(String username, String inResponseTo) {
        Assertion assertion = TestOpenSamlObjects.assertion(username);
        assertion.setIssueInstant(Instant.now());
        for (SubjectConfirmation confirmation : assertion.getSubject().getSubjectConfirmations()) {
            SubjectConfirmationData data = confirmation.getSubjectConfirmationData();
            data.setNotBefore(Instant.now().minus(Duration.ofMillis(5 * 60 * 1000)));
            data.setNotOnOrAfter(Instant.now().plus(Duration.ofMillis(5 * 60 * 1000)));
            if (StringUtils.hasText(inResponseTo)) {
                data.setInResponseTo(inResponseTo);
            }
        }
        Conditions conditions = assertion.getConditions();
        conditions.setNotBefore(Instant.now().minus(Duration.ofMillis(5 * 60 * 1000)));
        conditions.setNotOnOrAfter(Instant.now().plus(Duration.ofMillis(5 * 60 * 1000)));
        return assertion;
    }

    private static List<AttributeStatement> attributeStatements(List<AttributeStatement> attributeStatements) {
        AttributeBuilder attributeBuilder = new AttributeBuilder();
        Attribute registeredDateAttr = attributeBuilder.buildObject();
        registeredDateAttr.setName("registeredDate");
        XSDateTime registeredDate = new XSDateTimeBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                XSDateTime.TYPE_NAME);
        registeredDate.setValue(Instant.parse("1970-01-01T00:00:00Z"));
        registeredDateAttr.getAttributeValues().add(registeredDate);
        attributeStatements.iterator().next().getAttributes().add(registeredDateAttr);
        return attributeStatements;
    }

    public static Saml2AuthenticationToken token(Response response, RelyingPartyRegistration.Builder registration,
                                                 AbstractSaml2AuthenticationRequest authenticationRequest) {
        return new Saml2AuthenticationToken(registration.build(), serialize(response), authenticationRequest);
    }

    public static AbstractSaml2AuthenticationRequest mockedStoredAuthenticationRequest(String requestId,
                                                                                       Saml2MessageBinding binding, boolean corruptRequestString) {
        AuthnRequest request = request();
        if (requestId != null) {
            request.setID(requestId);
        }
        String serializedRequest = serializedRequest(request, binding);
        if (corruptRequestString) {
            serializedRequest = serializedRequest.substring(2, serializedRequest.length() - 2);
        }
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mock(AbstractSaml2AuthenticationRequest.class);
        given(mockAuthenticationRequest.getSamlRequest()).willReturn(serializedRequest);
        given(mockAuthenticationRequest.getBinding()).willReturn(binding);
        return mockAuthenticationRequest;
    }

    public static RelyingPartyRegistration.Builder registration() {
        return TestRelyingPartyRegistrations.noCredentials()
                .entityId(RELYING_PARTY_ENTITY_ID)
                .assertionConsumerServiceLocation(DESTINATION)
                .assertingPartyDetails(party -> party.entityId(ASSERTING_PARTY_ENTITY_ID));
    }

    public static RelyingPartyRegistration.Builder verifying(RelyingPartyRegistration.Builder builder) {
        return builder.assertingPartyDetails(party -> party
                .verificationX509Credentials(c -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())));
    }

    private static RelyingPartyRegistration.Builder decrypting(RelyingPartyRegistration.Builder builder) {
        return builder
                .decryptionX509Credentials(c -> c.add(TestSaml2X509Credentials.relyingPartyDecryptingCredential()));
    }

    public static Map<String, String> xmlNamespaces() {
        return Map.of(
                // Metadata
                "md", "urn:oasis:names:tc:SAML:2.0:metadata",
                "ds", "http://www.w3.org/2000/09/xmldsig#",
                // Request
                "saml2p", "urn:oasis:names:tc:SAML:2.0:protocol",
                "saml2", "urn:oasis:names:tc:SAML:2.0:assertion",
                // Response
                "samlp", "urn:oasis:names:tc:SAML:2.0:protocol",
                "saml", "urn:oasis:names:tc:SAML:2.0:assertion"
        );
    }
}
