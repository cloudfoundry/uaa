package org.cloudfoundry.identity.uaa.provider.saml;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.cloudfoundry.identity.uaa.provider.saml.OpenSaml4AuthenticationProvider.ResponseToken;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
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
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedAttribute;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.Authentication;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.Consumer;

import static java.util.Map.entry;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * This was copied from Spring Security, Test Classes and modified to work with the modified OpenSaml4AuthenticationProvider.
 * <p/>
 * Once we can move to the spring-security version of OpenSaml4AuthenticationProvider,
 * this class should be removed, along with OpenSamlDecryptionUtils and OpenSamlVerificationUtils.
 * <p/>
 * Modified Tests:
 * authenticateWhenAssertionContainsAttributesThenItSucceeds
 * deserializeWhenAssertionContainsAttributesThenWorks
 * <p/>
 * Tests for {@link OpenSaml4AuthenticationProvider}
 *
 * @author Filip Hanik
 * @author Josh Cummings
 */
class OpenSaml4AuthenticationProviderUnitTests {

    private static final String DESTINATION = "http://localhost:8080/uaa/saml/SSO/alias/integration-saml-entity-id";

    private static final String RELYING_PARTY_ENTITY_ID = "https://localhost/saml2/service-provider-metadata/idp-alias";

    private static final String ASSERTING_PARTY_ENTITY_ID = "https://some.idp.test/saml2/idp";

    private final OpenSaml4AuthenticationProvider provider = new OpenSaml4AuthenticationProvider();

    @AfterEach void cleanup() {
        IdentityZoneHolder.clear();
    }

    @Test
    void supportsWhenSaml2AuthenticationTokenThenReturnTrue() {
        assertThat(this.provider.supports(Saml2AuthenticationToken.class))
                .withFailMessage(OpenSaml4AuthenticationProvider.class + "should support " + Saml2AuthenticationToken.class)
                .isTrue();
    }

    @Test
    void supportsWhenNotSaml2AuthenticationTokenThenReturnFalse() {
        assertThat(this.provider.supports(Authentication.class))
                .withFailMessage(OpenSaml4AuthenticationProvider.class + "should not support " + Authentication.class)
                .isFalse();
    }

    @Test
    void authenticateWhenUnknownDataClassThenThrowAuthenticationException() {
        Assertion assertion = (Assertion) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(Assertion.DEFAULT_ELEMENT_NAME)
                .buildObject(Assertion.DEFAULT_ELEMENT_NAME);
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider
                        .authenticate(new Saml2AuthenticationToken(verifying(registration()).build(), serialize(assertion))))
                .satisfies(errorOf(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA));
    }

    @Test
    void authenticateWhenXmlErrorThenThrowAuthenticationException() {
        Saml2AuthenticationToken token = new Saml2AuthenticationToken(verifying(registration()).build(), "invalid xml");
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA));
    }

    @Test
    void authenticateWhenInvalidDestinationThenThrowAuthenticationException() {
        Response response = response(DESTINATION + "invalid", ASSERTING_PARTY_ENTITY_ID);
        response.getAssertions().add(assertion());
        Saml2AuthenticationToken token = token(signed(response), verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.INVALID_DESTINATION));
    }

    @Test
    void authenticateWhenNoAssertionsPresentThenThrowAuthenticationException() {
        Saml2AuthenticationToken token = token();
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.MALFORMED_RESPONSE_DATA, "No assertions found in response."));
    }

    @Test
    void authenticateWhenInvalidSignatureOnAssertionThenThrowAuthenticationException() {
        Response response = response();
        response.getAssertions().add(assertion());
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.INVALID_SIGNATURE));
    }

    @Test
    void authenticateWhenOpenSAMLValidationErrorThenThrowAuthenticationException() {
        Response response = response();
        Assertion assertion = assertion();
        assertion.getSubject()
                .getSubjectConfirmations()
                .getFirst()
                .getSubjectConfirmationData()
                .setNotOnOrAfter(Instant.now().minus(Duration.ofDays(3)));
        response.getAssertions().add(signed(assertion));
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.INVALID_ASSERTION));
    }

    @Test
    void authenticateWhenMissingSubjectThenThrowAuthenticationException() {
        Response response = response();
        Assertion assertion = assertion();
        assertion.setSubject(null);
        response.getAssertions().add(signed(assertion));
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.SUBJECT_NOT_FOUND));
    }

    @Test
    void authenticateWhenUsernameMissingThenThrowAuthenticationException() {
        Response response = response();
        Assertion assertion = assertion();
        assertion.getSubject().getNameID().setValue(null);
        response.getAssertions().add(signed(assertion));
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.SUBJECT_NOT_FOUND));
    }

    @Test
    void authenticateWhenAssertionContainsValidationAddressThenItSucceeds() {
        Response response = response();
        Assertion assertion = assertion();
        assertion.getSubject()
                .getSubjectConfirmations()
                .forEach(sc -> sc.getSubjectConfirmationData().setAddress("10.10.10.10"));
        response.getAssertions().add(signed(assertion));
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        this.provider.authenticate(token);
    }

    @Test
    void evaluateInResponseToSucceedsWhenInResponseToInResponseAndAssertionsMatchRequestID() {
        Response response = response();
        response.setInResponseTo("SAML2");
        response.getAssertions().add(signed(assertion("SAML2")));
        response.getAssertions().add(signed(assertion("SAML2")));
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, false);
        Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
        this.provider.authenticate(token);
    }

    @Test
    void evaluateInResponseToSucceedsWhenInResponseToInAssertionOnlyMatchRequestID() {
        Response response = response();
        response.getAssertions().add(signed(assertion()));
        response.getAssertions().add(signed(assertion("SAML2")));
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, false);
        Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
        this.provider.authenticate(token);
    }

    @Test
    void evaluateInResponseToSucceedsWhenInResponseToRedirectAssertionOnlyMatchRequestID() {
        Response response = response();
        response.getAssertions().add(signed(assertion()));
        response.getAssertions().add(signed(assertion("SAML2")));
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.REDIRECT, false);
        Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
        this.provider.authenticate(token);
    }

    @Test
    void evaluateInResponseToFailsWhenInResponseToInAssertionOnlyAndCorruptedStoredRequest() {
        Response response = response();
        response.getAssertions().add(signed(assertion()));
        response.getAssertions().add(signed(assertion("SAML2")));
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, true);
        Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .withStackTraceContaining("malformed_request_data");
    }

    @Test
    void evaluateInResponseToFailsWhenInResponseToInAssertionMismatchWithRequestID() {
        Response response = response();
        response.setInResponseTo("SAML2");
        response.getAssertions().add(signed(assertion("SAML2")));
        response.getAssertions().add(signed(assertion("BAD")));
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, false);
        Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .withStackTraceContaining("invalid_assertion");
    }

    @Test
    void evaluateInResponseToFailsWhenInResponseToInAssertionOnlyAndMismatchWithRequestID() {
        Response response = response();
        response.getAssertions().add(signed(assertion()));
        response.getAssertions().add(signed(assertion("BAD")));
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, false);
        Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .withStackTraceContaining("invalid_assertion");
    }

    @Test
    void evaluateInResponseToFailsWhenInResponseInToResponseMismatchWithRequestID() {
        Response response = response();
        response.setInResponseTo("BAD");
        response.getAssertions().add(signed(assertion("SAML2")));
        response.getAssertions().add(signed(assertion("SAML2")));
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, false);
        Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .withStackTraceContaining("invalid_in_response_to");
    }

    @Test
    void evaluateInResponseToFailsWhenInResponseInToResponseAndCorruptedStoredRequest() {
        Response response = response();
        response.setInResponseTo("SAML2");
        response.getAssertions().add(signed(assertion()));
        response.getAssertions().add(signed(assertion()));
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, true);
        Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .withStackTraceContaining("malformed_request_data");
    }

    @Test
    void evaluateInResponseToFailsWhenInResponseToInResponseButNoSavedRequest() {
        Response response = response();
        response.setInResponseTo("BAD");
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .withStackTraceContaining("invalid_in_response_to");
    }

    @Test
    void evaluateInResponseToSucceedsWhenNoInResponseToInResponseOrAssertions() {
        Response response = response();
        response.getAssertions().add(signed(assertion()));
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, false);
        Saml2AuthenticationToken token = token(response, verifying(registration()), mockAuthenticationRequest);
        this.provider.authenticate(token);
    }

    @Test
    void authenticateWhenAssertionContainsAttributesThenItSucceeds() {
        Response response = response();
        Assertion assertion = assertion();
        List<AttributeStatement> attributes = attributeStatements();
        assertion.getAttributeStatements().addAll(attributes);
        response.getAssertions().add(signed(assertion));
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        Authentication authentication = this.provider.authenticate(token);
        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();

        Instant registeredDate = Instant.parse("1970-01-01T00:00:00Z");
        assertThat(principal.getAttributes())
                .contains(entry("email", List.of("john.doe@example.com", "doe.john@example.com")))
                .contains(entry("name", List.of("John Doe")))
                .contains(entry("age", List.of(21)))
                .contains(entry("website", List.of("https://johndoe.com/")))
                .contains(entry("registered", List.of(true)))
                .contains(entry("age", List.of(21)))
                .contains(entry("registeredDate", List.of(registeredDate)))
                .contains(entry("role", List.of("RoleOne", "RoleTwo")));
        assertThat(principal.getSessionIndexes())
                .contains("session-index");
    }

    // gh-11785
    @Test
    void deserializeWhenAssertionContainsAttributesThenWorks() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ClassLoader loader = getClass().getClassLoader();
        mapper.registerModules(SecurityJackson2Modules.getModules(loader));
        Response response = response();
        Assertion assertion = assertion();
        List<AttributeStatement> attributes = TestOpenSamlObjects.attributeStatements();
        attributes.subList(2, attributes.size()).clear();
        assertion.getAttributeStatements().addAll(attributes);
        response.getAssertions().add(signed(assertion));
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        Authentication authentication = this.provider.authenticate(token);
        String result = mapper.writeValueAsString(authentication);
        mapper.readValue(result, Authentication.class);
    }

    @Test
    void authenticateWhenAssertionContainsCustomAttributesThenItSucceeds() {
        Response response = response();
        Assertion assertion = assertion();
        AttributeStatement attribute = TestOpenSamlObjects.customAttributeStatement("Address",
                TestCustomOpenSamlObjects.instance());
        assertion.getAttributeStatements().add(attribute);
        response.getAssertions().add(signed(assertion));
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        Authentication authentication = this.provider.authenticate(token);
        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
        TestCustomOpenSamlObjects.CustomOpenSamlObject address = (TestCustomOpenSamlObjects.CustomOpenSamlObject) principal.getAttribute("Address").getFirst();
        assertThat(address.getStreet()).isEqualTo("Test Street");
        assertThat(address.getStreetNumber()).isEqualTo("1");
        assertThat(address.getZIP()).isEqualTo("11111");
        assertThat(address.getCity()).isEqualTo("Test City");
    }

    @Test
    void authenticateWhenEncryptedAssertionWithoutSignatureThenItFails() {
        Response response = response();
        EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        response.getEncryptedAssertions().add(encryptedAssertion);
        Saml2AuthenticationToken token = token(response, decrypting(verifying(registration())));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.INVALID_SIGNATURE, "Did not decrypt response"));
    }

    @Test
    void authenticateWhenEncryptedAssertionWithoutSignatureThenAllowItIfSamlConfigurationAllowsIt() {
        IdentityZone identityZone = IdentityZoneHolder.getUaaZone();
        identityZone.getConfig().getSamlConfig().setWantAssertionSigned(false);
        IdentityZoneHolder.set(identityZone);
        Response response = response();
        EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        response.getEncryptedAssertions().add(encryptedAssertion);
        Saml2AuthenticationToken token = token(response, decrypting(verifying(registration())));
        assertThatNoException().isThrownBy(() -> this.provider.authenticate(token));
    }

    @Test
    void authenticateWhenEncryptedAssertionWithSignatureThenItSucceeds() {
        Response response = response();
        Assertion assertion = TestOpenSamlObjects.signed(assertion(),
                TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
        EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion,
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        response.getEncryptedAssertions().add(encryptedAssertion);
        Saml2AuthenticationToken token = token(signed(response), decrypting(verifying(registration())));
        this.provider.authenticate(token);
    }

    @Test
    void authenticateWhenEncryptedAssertionWithResponseSignatureThenItSucceeds() {
        Response response = response();
        EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        response.getEncryptedAssertions().add(encryptedAssertion);
        Saml2AuthenticationToken token = token(signed(response), decrypting(verifying(registration())));
        this.provider.authenticate(token);
    }

    @Test
    void authenticateWhenEncryptedNameIdWithSignatureThenItSucceeds() {
        Response response = response();
        Assertion assertion = assertion();
        NameID nameId = assertion.getSubject().getNameID();
        EncryptedID encryptedID = TestOpenSamlObjects.encrypted(nameId,
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        assertion.getSubject().setNameID(null);
        assertion.getSubject().setEncryptedID(encryptedID);
        response.getAssertions().add(signed(assertion));
        Saml2AuthenticationToken token = token(response, decrypting(verifying(registration())));
        this.provider.authenticate(token);
    }

    @Test
    void authenticateWhenEncryptedAttributeThenDecrypts() {
        Response response = response();
        Assertion assertion = assertion();
        EncryptedAttribute attribute = TestOpenSamlObjects.encrypted("name", "value",
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        AttributeStatement statement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
        statement.getEncryptedAttributes().add(attribute);
        assertion.getAttributeStatements().add(statement);
        response.getAssertions().add(assertion);
        Saml2AuthenticationToken token = token(signed(response), decrypting(verifying(registration())));
        Saml2Authentication authentication = (Saml2Authentication) this.provider.authenticate(token);
        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
        assertThat(principal.getAttribute("name")).containsExactly("value");
    }

    @Test
    void authenticateWhenDecryptionKeysAreMissingThenThrowAuthenticationException() {
        Response response = response();
        EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        response.getEncryptedAssertions().add(encryptedAssertion);
        Saml2AuthenticationToken token = token(signed(response), verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.DECRYPTION_ERROR, "Failed to decrypt EncryptedData"));
    }

    @Test
    void authenticateWhenDecryptionKeysAreWrongThenThrowAuthenticationException() {
        Response response = response();
        EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion(),
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        response.getEncryptedAssertions().add(encryptedAssertion);
        Saml2AuthenticationToken token = token(signed(response), registration()
                .decryptionX509Credentials(c -> c.add(TestSaml2X509Credentials.assertingPartyPrivateCredential())));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.DECRYPTION_ERROR, "Failed to decrypt EncryptedData"));
    }

    @Test
    void authenticateWhenAuthenticationHasDetailsThenSucceeds() {
        Response response = response();
        Assertion assertion = assertion();
        assertion.getSubject()
                .getSubjectConfirmations()
                .forEach(sc -> sc.getSubjectConfirmationData().setAddress("10.10.10.10"));
        response.getAssertions().add(signed(assertion));
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        token.setDetails("some-details");
        Authentication authentication = this.provider.authenticate(token);
        assertThat(authentication.getDetails()).isEqualTo("some-details");
    }

    @Test
    void writeObjectWhenTypeIsSaml2AuthenticationThenNoException() throws IOException {
        Response response = response();
        Assertion assertion = TestOpenSamlObjects.signed(assertion(),
                TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
        EncryptedAssertion encryptedAssertion = TestOpenSamlObjects.encrypted(assertion,
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        response.getEncryptedAssertions().add(encryptedAssertion);
        Saml2AuthenticationToken token = token(signed(response), decrypting(verifying(registration())));
        Saml2Authentication authentication = (Saml2Authentication) this.provider.authenticate(token);
        // the following code will throw an exception if authentication isn't serializable
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream(1024);
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteStream);
        objectOutputStream.writeObject(authentication);
        objectOutputStream.flush();
    }

    @Test
    void createDefaultAssertionValidatorWhenAssertionThenValidates() {
        Response response = TestOpenSamlObjects.signedResponseWithOneAssertion();
        Assertion assertion = response.getAssertions().getFirst();
        OpenSaml4AuthenticationProvider.AssertionToken assertionToken = new OpenSaml4AuthenticationProvider.AssertionToken(
                assertion, token());
        assertThat(
                OpenSaml4AuthenticationProvider.createDefaultAssertionValidator().convert(assertionToken).hasErrors())
                .isFalse();
    }

    @Test
    void authenticateWithSHA1SignatureThenItSucceeds() throws Exception {
        Response response = response();
        Assertion assertion = TestOpenSamlObjects.signed(assertion(),
                TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID,
                SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        response.getAssertions().add(assertion);
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        this.provider.authenticate(token);
    }

    @Test
    void createDefaultResponseAuthenticationConverterWhenResponseThenConverts() {
        Response response = TestOpenSamlObjects.signedResponseWithOneAssertion();
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        ResponseToken responseToken = new ResponseToken(response, token);
        Saml2Authentication authentication = OpenSaml4AuthenticationProvider
                .createDefaultResponseAuthenticationConverter()
                .convert(responseToken);
        assertThat(authentication.getName()).isEqualTo("test@saml.user");
    }

    @Test
    void authenticateWhenResponseAuthenticationConverterConfiguredThenUses() {
        Converter<ResponseToken, Saml2Authentication> authenticationConverter = mock(Converter.class);
        provider.setResponseAuthenticationConverter(authenticationConverter);
        Response response = TestOpenSamlObjects.signedResponseWithOneAssertion();
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        provider.authenticate(token);
        verify(authenticationConverter).convert(any());
    }

    @Test
    void setResponseAuthenticationConverterWhenNullThenIllegalArgument() {
        // @formatter:off
        assertThatIllegalArgumentException()
                .isThrownBy(() -> this.provider.setResponseAuthenticationConverter(null));
        // @formatter:on
    }

    @Test
    void authenticateWhenResponseStatusIsNotSuccessThenFails() {
        Response response = TestOpenSamlObjects
                .signedResponseWithOneAssertion(r -> r.setStatus(TestOpenSamlObjects.status(StatusCode.AUTHN_FAILED)));
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.INVALID_RESPONSE, "Invalid status"));
    }

    @Test
    void authenticateWhenResponseStatusIsSuccessThenSucceeds() {
        Response response = TestOpenSamlObjects
                .signedResponseWithOneAssertion(r -> r.setStatus(TestOpenSamlObjects.successStatus()));
        Saml2AuthenticationToken token = token(response, verifying(registration()));
        Authentication authentication = this.provider.authenticate(token);
        assertThat(authentication.getName()).isEqualTo("test@saml.user");
    }

    @Test
    void setResponseValidatorWhenNullThenIllegalArgument() {
        assertThatIllegalArgumentException().isThrownBy(() -> this.provider.setResponseValidator(null));
    }

    @Test
    void authenticateWhenCustomResponseValidatorThenUses() {
        Converter<ResponseToken, Saml2ResponseValidatorResult> validator = mock(Converter.class);
        // @formatter:off
        provider.setResponseValidator(responseToken -> OpenSaml4AuthenticationProvider.createDefaultResponseValidator()
                        .convert(responseToken)
                        .concat(validator.convert(responseToken))
        );
        // @formatter:on
        Response response = response();
        Assertion assertion = assertion();
        response.getAssertions().add(assertion);
        Saml2AuthenticationToken token = token(signed(response), verifying(registration()));
        given(validator.convert(any(ResponseToken.class)))
                .willReturn(Saml2ResponseValidatorResult.success());
        provider.authenticate(token);
        verify(validator).convert(any(ResponseToken.class));
    }

    @Test
    void authenticateWhenAssertionIssuerNotValidThenFailsWithInvalidIssuer() {
        Response response = response();
        Assertion assertion = assertion();
        assertion.setIssuer(TestOpenSamlObjects.issuer("https://invalid.idp.test/saml2/idp"));
        response.getAssertions().add(assertion);
        Saml2AuthenticationToken token = token(signed(response), verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class).isThrownBy(() -> provider.authenticate(token))
                .withMessageContaining("did not match any valid issuers");
    }

    private <T extends XMLObject> T build(QName qName) {
        return (T) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(qName).buildObject(qName);
    }

    private String serialize(XMLObject object) {
        try {
            Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
            Element element = marshaller.marshall(object);
            return SerializeSupport.nodeToString(element);
        } catch (MarshallingException ex) {
            throw new Saml2Exception(ex);
        }
    }

    private Consumer<Saml2AuthenticationException> errorOf(String errorCode) {
        return errorOf(errorCode, null);
    }

    private Consumer<Saml2AuthenticationException> errorOf(String errorCode, String description) {
        return ex -> {
            assertThat(ex.getSaml2Error().getErrorCode()).isEqualTo(errorCode);
            if (StringUtils.hasText(description)) {
                assertThat(ex.getSaml2Error().getDescription()).contains(description);
            }
        };
    }

    private Response response() {
        Response response = TestOpenSamlObjects.response();
        response.setIssueInstant(Instant.now());
        return response;
    }

    private Response response(String destination, String issuerEntityId) {
        Response response = TestOpenSamlObjects.response(destination, issuerEntityId);
        response.setIssueInstant(Instant.now());
        return response;
    }

    private AuthnRequest request() {
        return TestOpenSamlObjects.authnRequest();
    }

    private String serializedRequest(AuthnRequest request, Saml2MessageBinding binding) {
        String xml = serialize(request);
        return binding == Saml2MessageBinding.POST ? Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8))
                : Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
    }

    private Assertion assertion(String inResponseTo) {
        Assertion assertion = TestOpenSamlObjects.assertion();
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

    private Assertion assertion() {
        return assertion(null);
    }

    private <T extends SignableSAMLObject> T signed(T toSign) {
        TestOpenSamlObjects.signed(toSign, TestSaml2X509Credentials.assertingPartySigningCredential(),
                RELYING_PARTY_ENTITY_ID);
        return toSign;
    }

    private List<AttributeStatement> attributeStatements() {
        List<AttributeStatement> attributeStatements = TestOpenSamlObjects.attributeStatements();
        AttributeBuilder attributeBuilder = new AttributeBuilder();
        Attribute registeredDateAttr = attributeBuilder.buildObject();
        registeredDateAttr.setName("registeredDate");
        XSDateTime registeredDate = new XSDateTimeBuilder().buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
                XSDateTime.TYPE_NAME);
        registeredDate.setValue(Instant.parse("1970-01-01T00:00:00Z"));
        registeredDateAttr.getAttributeValues().add(registeredDate);
        attributeStatements.getFirst().getAttributes().add(registeredDateAttr);
        return attributeStatements;
    }

    private Saml2AuthenticationToken token() {
        Response response = response();
        RelyingPartyRegistration registration = verifying(registration()).build();
        return new Saml2AuthenticationToken(registration, serialize(response));
    }

    private Saml2AuthenticationToken token(Response response, RelyingPartyRegistration.Builder registration) {
        return new Saml2AuthenticationToken(registration.build(), serialize(response));
    }

    private Saml2AuthenticationToken token(Response response, RelyingPartyRegistration.Builder registration,
            AbstractSaml2AuthenticationRequest authenticationRequest) {
        return new Saml2AuthenticationToken(registration.build(), serialize(response), authenticationRequest);
    }

    private AbstractSaml2AuthenticationRequest mockedStoredAuthenticationRequest(String requestId,
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

    private RelyingPartyRegistration.Builder registration() {
        return TestRelyingPartyRegistrations.noCredentials()
                .entityId(RELYING_PARTY_ENTITY_ID)
                .assertionConsumerServiceLocation(DESTINATION)
                .assertingPartyDetails(party -> party.entityId(ASSERTING_PARTY_ENTITY_ID));
    }

    private RelyingPartyRegistration.Builder verifying(RelyingPartyRegistration.Builder builder) {
        return builder.assertingPartyDetails(party -> party
                .verificationX509Credentials(c -> c.add(TestSaml2X509Credentials.relyingPartyVerifyingCredential())));
    }

    private RelyingPartyRegistration.Builder decrypting(RelyingPartyRegistration.Builder builder) {
        return builder
                .decryptionX509Credentials(c -> c.add(TestSaml2X509Credentials.relyingPartyDecryptingCredential()));
    }
}
