package org.cloudfoundry.identity.uaa.provider.saml;

import com.fasterxml.jackson.databind.ObjectMapper;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.cloudfoundry.identity.uaa.impl.config.RestTemplateConfig;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.junit.jupiter.api.BeforeEach;
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
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAttribute;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
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
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * This is based on OpenSaml4AuthenticationProviderTest from Spring Security
 */
class Saml2BearerGrantAuthenticationConverterTest {

    private static final String DESTINATION = "http://localhost:8080/uaa/oauth/token/alias/integration-saml-entity-id";

    private static final String RELYING_PARTY_ENTITY_ID = "https://localhost/saml2/service-provider-metadata/idp-alias";

    private static final String ASSERTING_PARTY_ENTITY_ID = "https://some.idp.test/saml2/idp";

    private Saml2BearerGrantAuthenticationConverter provider;

    @BeforeEach
    void beforeEach() {
        IdentityZoneManager identityZoneManager = new IdentityZoneManagerImpl();
        SamlConfiguration samlConfiguration = new SamlConfiguration();
        JdbcIdentityProviderProvisioning providerProvisioning = mock(JdbcIdentityProviderProvisioning.class);

        SamlIdentityProviderConfigurator identityProviderConfigurator = new SamlIdentityProviderConfigurator(
                providerProvisioning, identityZoneManager, samlConfiguration.fixedHttpMetaDataProvider(RestTemplateConfig.createDefaults(), null)
        );
        SamlRelyingPartyRegistrationRepositoryConfig samlRelyingPartyRegistrationRepositoryConfig =
                new SamlRelyingPartyRegistrationRepositoryConfig(
                        "integration-saml-entity-id", Saml2TestUtils.createTestSamlProperties(),
                        new BootstrapSamlIdentityProviderData(identityProviderConfigurator),
                        "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                        List.of(SignatureAlgorithm.SHA256, SignatureAlgorithm.SHA512));

        RelyingPartyRegistrationRepository relyingPartyRegistrationRepository = samlRelyingPartyRegistrationRepositoryConfig.relyingPartyRegistrationRepository(identityProviderConfigurator);
        RelyingPartyRegistrationResolver relyingPartyRegistrationResolver = samlRelyingPartyRegistrationRepositoryConfig.relyingPartyRegistrationResolver(relyingPartyRegistrationRepository, null);

        provider = new Saml2BearerGrantAuthenticationConverter(relyingPartyRegistrationResolver, identityZoneManager,
               null);
    }

    @Test
    void authenticateWhenUnknownDataClassThenThrowAuthenticationException() {
        Audience audience = (Audience) XMLObjectProviderRegistrySupport.getBuilderFactory()
                .getBuilder(Audience.DEFAULT_ELEMENT_NAME)
                .buildObject(Audience.DEFAULT_ELEMENT_NAME);
        Saml2AuthenticationToken token = new Saml2AuthenticationToken(verifying(registration()).build(), serialize(audience));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.INVALID_ASSERTION));
    }

    @Test
    void authenticateWhenXmlErrorThenThrowAuthenticationException() {
        Saml2AuthenticationToken token = new Saml2AuthenticationToken(verifying(registration()).build(), "invalid xml");
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.INVALID_ASSERTION));
    }

    @Test
    void authenticateWhenInvalidDestinationThenThrowAuthenticationException() {
        Assertion assertion = assertion(null, DESTINATION + "invalid");

        Saml2AuthenticationToken token = token(signed(assertion), verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.INVALID_ASSERTION));
    }

    @Test
    void authenticateWhenInvalidSignatureOnAssertionThenThrowAuthenticationException() {
        Assertion assertion = signed(assertion());
        assertion.setID("changed");
        Saml2AuthenticationToken token = token(assertion, verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.INVALID_SIGNATURE));
    }

    @Test
    void authenticateWhenOpenSAMLValidationErrorThenThrowAuthenticationException() {
        Assertion assertion = assertion();
        assertion.getSubject()
                .getSubjectConfirmations()
                .getFirst()
                .getSubjectConfirmationData()
                .setNotOnOrAfter(Instant.now().minus(Duration.ofDays(3)));

        Saml2AuthenticationToken token = token(assertion, verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.INVALID_ASSERTION));
    }

    @Test
    void authenticateWhenMissingSubjectThenThrowAuthenticationException() {
        Assertion assertion = assertion();
        assertion.setSubject(null);

        Saml2AuthenticationToken token = token(assertion, verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.SUBJECT_NOT_FOUND));
    }

    @Test
    void authenticateWhenUsernameMissingThenThrowAuthenticationException() {
        Assertion assertion = assertion();
        assertion.getSubject().getNameID().setValue(null);
        Saml2AuthenticationToken token = token(assertion, verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.SUBJECT_NOT_FOUND));
    }

    @Test
    void authenticateWhenAssertionContainsValidationAddressThenItSucceeds() {
        Assertion assertion = assertion();
        assertion.getSubject()
                .getSubjectConfirmations()
                .forEach(sc -> sc.getSubjectConfirmationData().setAddress("10.10.10.10"));
        Saml2AuthenticationToken token = token(assertion, verifying(registration()));
        this.provider.authenticate(token);
    }

    @Test
    void evaluateInResponseToSucceedsWhenInResponseToInAssertionOnlyMatchRequestID() {
        Assertion assertion = assertion();
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, false);
        Saml2AuthenticationToken token = token(assertion, verifying(registration()), mockAuthenticationRequest);
        this.provider.authenticate(token);
    }

    @Test
    void evaluateInResponseToFailsWhenInResponseToInAssertionMismatchWithRequestID() {
        Assertion assertion = assertion("saml2");
        AbstractSaml2AuthenticationRequest mockAuthenticationRequest = mockedStoredAuthenticationRequest("SAML2",
                Saml2MessageBinding.POST, false);
        Saml2AuthenticationToken token = token(assertion, verifying(registration()), mockAuthenticationRequest);
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .withStackTraceContaining("invalid_assertion");
    }

    @Test
    void authenticateWhenAssertionContainsAttributesThenItSucceeds() {
        Assertion assertion = assertion();
        List<AttributeStatement> attributes = attributeStatements();
        assertion.getAttributeStatements().addAll(attributes);
        Saml2AuthenticationToken token = token(assertion, verifying(registration()));
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
        Assertion assertion = assertion();
        List<AttributeStatement> attributes = TestOpenSamlObjects.attributeStatements();
        attributes.subList(2, attributes.size()).clear();

        assertion.getAttributeStatements().addAll(attributes);
        Saml2AuthenticationToken token = token(assertion, verifying(registration()));
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
        Saml2AuthenticationToken token = token(assertion, verifying(registration()));
        Authentication authentication = this.provider.authenticate(token);
        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
        TestCustomOpenSamlObjects.CustomOpenSamlObject address = (TestCustomOpenSamlObjects.CustomOpenSamlObject) principal.getAttribute("Address").getFirst();
        assertThat(address.getStreet()).isEqualTo("Test Street");
        assertThat(address.getStreetNumber()).isEqualTo("1");
        assertThat(address.getZIP()).isEqualTo("11111");
        assertThat(address.getCity()).isEqualTo("Test City");
    }

    @Test
    void authenticateWhenEncryptedAttributeWithoutSignatureThenItFails() {
        Assertion assertion = assertion();
        EncryptedAttribute attribute = TestOpenSamlObjects.encrypted("name", "value",
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        AttributeStatement statement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
        statement.getEncryptedAttributes().add(attribute);
        assertion.getAttributeStatements().add(statement);

        Saml2AuthenticationToken token = token(signed(assertion), registration());
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.DECRYPTION_ERROR, "Failed to decrypt EncryptedData"));
    }

    @Test
    void authenticateWhenSignedAssertionWithSignatureThenItSucceeds() {
        Assertion assertion = TestOpenSamlObjects.signed(assertion(),
                TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
        Saml2AuthenticationToken token = token(signed(assertion), decrypting(verifying(registration())));
        this.provider.authenticate(token);
    }

    @Test
    void authenticateWithAssertionSignatureThenItSucceeds() {
        Assertion assertion = assertion();
        Saml2AuthenticationToken token = token(signed(assertion), decrypting(verifying(registration())));
        this.provider.authenticate(token);
    }

    @Test
    void authenticateWhenEncryptedAttributeThenDecrypts() {
        Assertion assertion = assertion();
        EncryptedAttribute attribute = TestOpenSamlObjects.encrypted("name", "value",
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        AttributeStatement statement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
        statement.getEncryptedAttributes().add(attribute);
        assertion.getAttributeStatements().add(statement);
        Saml2AuthenticationToken token = token(signed(assertion), decrypting(verifying(registration())));
        Saml2Authentication authentication = (Saml2Authentication) this.provider.authenticate(token);
        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
        assertThat(principal.getAttribute("name")).containsExactly("value");
    }

    @Test
    void authenticateWhenDecryptionKeysAreMissingThenThrowAuthenticationException() {
        Assertion assertion = assertion();
        EncryptedAttribute attribute = TestOpenSamlObjects.encrypted("name", "value",
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        AttributeStatement statement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
        statement.getEncryptedAttributes().add(attribute);
        assertion.getAttributeStatements().add(statement);

        Saml2AuthenticationToken token = token(signed(assertion), verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class)
                .isThrownBy(() -> this.provider.authenticate(token))
                .satisfies(errorOf(Saml2ErrorCodes.DECRYPTION_ERROR, "Failed to decrypt EncryptedData"));
    }

    @Test
    void authenticateWhenDecryptionKeysAreWrongThenThrowAuthenticationException() {
        Assertion assertion = assertion();
        EncryptedAttribute attribute = TestOpenSamlObjects.encrypted("name", "value",
                TestSaml2X509Credentials.assertingPartyEncryptingCredential());
        AttributeStatement statement = build(AttributeStatement.DEFAULT_ELEMENT_NAME);
        statement.getEncryptedAttributes().add(attribute);
        assertion.getAttributeStatements().add(statement);

        Saml2AuthenticationToken token = token(signed(assertion), registration()
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
        Saml2AuthenticationToken token = token(assertion, verifying(registration()));
        token.setDetails("some-details");
        Authentication authentication = this.provider.authenticate(token);
        assertThat(authentication.getDetails()).isEqualTo("some-details");
    }

    @Test
    void writeObjectWhenTypeIsSaml2AuthenticationThenNoException() throws IOException {
        Assertion assertion = TestOpenSamlObjects.signed(assertion(),
                TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID);
        Saml2AuthenticationToken token = token(signed(assertion), decrypting(verifying(registration())));
        Saml2Authentication authentication = (Saml2Authentication) this.provider.authenticate(token);
        // the following code will throw an exception if authentication isn't serializable
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream(1024);
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteStream);
        objectOutputStream.writeObject(authentication);
        objectOutputStream.flush();
    }

    @Test
    void createDefaultAssertionValidatorWhenAssertionThenValidates() {
        Assertion assertion = signed(assertion());
        OpenSaml4AuthenticationProvider.AssertionToken assertionToken = new OpenSaml4AuthenticationProvider.AssertionToken(
                assertion, token());
        assertThat(
                Saml2BearerGrantAuthenticationConverter.createDefaultAssertionValidator().convert(assertionToken).hasErrors())
                .isFalse();
    }

    @Test
    void authenticateWithSHA1SignatureThenItSucceeds() throws Exception {
        Assertion assertion = TestOpenSamlObjects.signed(assertion(),
                TestSaml2X509Credentials.assertingPartySigningCredential(), RELYING_PARTY_ENTITY_ID,
                SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);

        Saml2AuthenticationToken token = token(assertion, verifying(registration()));
        this.provider.authenticate(token);
    }

    @Test
    void createDefaultResponseAuthenticationConverterWhenResponseThenConverts() {
        Assertion assertion = assertion();
        Saml2AuthenticationToken token = token(assertion, verifying(registration()));
        OpenSaml4AuthenticationProvider.AssertionToken assertionToken = new OpenSaml4AuthenticationProvider.AssertionToken(assertion, token);
        AbstractAuthenticationToken authentication = Saml2BearerGrantAuthenticationConverter
                .createDefaultAssertionAuthenticationConverter()
                .convert(assertionToken);
        assertThat(authentication.getName()).isEqualTo("test@saml.user");
    }

    @Test
    void authenticateWhenAssertionIssuerNotValidThenFailsWithInvalidIssuer() {
        Assertion assertion = assertion();
        assertion.setIssuer(TestOpenSamlObjects.issuer("https://invalid.idp.test/saml2/idp"));
        Saml2AuthenticationToken token = token(signed(assertion), verifying(registration()));
        assertThatExceptionOfType(Saml2AuthenticationException.class).isThrownBy(() -> provider.authenticate(token))
                .withMessageContaining("from Issuer", "was not valid");
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

    private AuthnRequest request() {
        return TestOpenSamlObjects.authnRequest();
    }

    private String serializedRequest(AuthnRequest request, Saml2MessageBinding binding) {
        String xml = serialize(request);
        return binding == Saml2MessageBinding.POST ? Saml2Utils.samlBearerEncode(xml.getBytes(StandardCharsets.UTF_8))
                : Saml2Utils.samlBearerEncode(Saml2Utils.samlDeflate(xml));
    }

    private Assertion assertion(String inResponseTo) {
        return assertion(inResponseTo, DESTINATION);
    }

    private Assertion assertion(String inResponseTo, String destination) {
        Assertion assertion = TestOpenSamlObjects.assertion();
        assertion.setIssueInstant(Instant.now());

        for (SubjectConfirmation confirmation : assertion.getSubject().getSubjectConfirmations()) {
            SubjectConfirmationData data = confirmation.getSubjectConfirmationData();
            data.setRecipient(destination);
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
        Assertion assertion = assertion();
        RelyingPartyRegistration registration = verifying(registration()).build();
        return new Saml2AuthenticationToken(registration, serialize(assertion));
    }

    private Saml2AuthenticationToken token(Assertion assertion, RelyingPartyRegistration.Builder registration) {
        return new Saml2AuthenticationToken(registration.build(), serialize(assertion));
    }

    private Saml2AuthenticationToken token(Assertion assertion, RelyingPartyRegistration.Builder registration,
            AbstractSaml2AuthenticationRequest authenticationRequest) {
        return new Saml2AuthenticationToken(registration.build(), serialize(assertion), authenticationRequest);
    }

    private AbstractSaml2AuthenticationRequest mockedStoredAuthenticationRequest(String requestId,
            Saml2MessageBinding binding, boolean corruptRequestString) {
        AuthnRequest request = request();
        if (requestId != null) {
            request.setID(requestId);
        }
        String serializedRequest = serializedRequest(request, binding);
        if (corruptRequestString) {
            serializedRequest = serializedRequest.substring(48, serializedRequest.length() - 48);
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
