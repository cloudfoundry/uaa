package org.cloudfoundry.identity.uaa.provider.saml;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.common.assertion.ValidationResult;
import org.opensaml.saml.saml2.assertion.ConditionValidator;
import org.opensaml.saml.saml2.assertion.SAML20AssertionValidator;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.assertion.StatementValidator;
import org.opensaml.saml.saml2.assertion.SubjectConfirmationValidator;
import org.opensaml.saml.saml2.assertion.impl.AudienceRestrictionConditionValidator;
import org.opensaml.saml.saml2.assertion.impl.BearerSubjectConfirmationValidator;
import org.opensaml.saml.saml2.assertion.impl.DelegationRestrictionConditionValidator;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Condition;
import org.opensaml.saml.saml2.core.OneTimeUse;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AuthnRequestUnmarshaller;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.annotation.Nonnull;
import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * This class contains functions to Validate SAML assertions. It is based on the Spring-Security
 * class SAML20AssertionValidators within:
 * org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider
 * <p>
 * But that class is not compatible with OpenSaml 4.0.x
 */
public class OpenSaml40CompatibleAssertionValidators {

    private static final AuthnRequestUnmarshaller authnRequestUnmarshaller;
    private static final Collection<ConditionValidator> conditions = new ArrayList<>();
    private static final Collection<SubjectConfirmationValidator> subjects = new ArrayList<>();
    private static final Collection<StatementValidator> statements = new ArrayList<>();
    private static final SignaturePrevalidator validator = new SAMLSignatureProfileValidator();
    private static final SAML20AssertionValidator attributeValidator = new SAML20AssertionValidator(conditions,
            subjects, statements, null, null) {
        @Nonnull
        @Override
        protected ValidationResult validateSignature(Assertion token, ValidationContext context) {
            return ValidationResult.VALID;
        }
    };

    static {
        XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
        authnRequestUnmarshaller = (AuthnRequestUnmarshaller) registry.getUnmarshallerFactory()
                .getUnmarshaller(AuthnRequest.DEFAULT_ELEMENT_NAME);
    }

    static {
        conditions.add(new AudienceRestrictionConditionValidator());
        conditions.add(new DelegationRestrictionConditionValidator());
        conditions.add(new ConditionValidator() {
            @Nonnull
            @Override
            public QName getServicedCondition() {
                return OneTimeUse.DEFAULT_ELEMENT_NAME;
            }

            @Nonnull
            @Override
            public ValidationResult validate(Condition condition, Assertion assertion, ValidationContext context) {
                // applications should validate their own OneTimeUse conditions
                return ValidationResult.VALID;
            }
        });
        subjects.add(new BearerSubjectConfirmationValidator() {
            @Override
            protected ValidationResult validateAddress(SubjectConfirmation confirmation, Assertion assertion,
                                                       ValidationContext context, boolean required) {
                // applications should validate their own addresses - gh-7514
                return ValidationResult.VALID;
            }
        });
    }

    public static Converter<OpenSaml4AuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionValidator() {

        return createDefaultAssertionValidatorWithParameters(
                (params) -> params.put(SAML2AssertionValidationParameters.CLOCK_SKEW, Duration.ofMinutes(5)));
    }

    public static Converter<OpenSaml4AuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionValidatorWithParameters(
            Consumer<Map<String, Object>> validationContextParameters) {
        return createAssertionValidator(Saml2ErrorCodes.INVALID_ASSERTION,
                (assertionToken) -> OpenSaml40CompatibleAssertionValidators.attributeValidator,
                (assertionToken) -> createValidationContext(assertionToken, validationContextParameters));
    }

    private static ValidationContext createValidationContext(OpenSaml4AuthenticationProvider.AssertionToken assertionToken,
                                                             Consumer<Map<String, Object>> paramsConsumer) {
        Saml2AuthenticationToken token = assertionToken.getToken();
        RelyingPartyRegistration relyingPartyRegistration = token.getRelyingPartyRegistration();
        String audience = relyingPartyRegistration.getEntityId();
        String recipient = relyingPartyRegistration.getAssertionConsumerServiceLocation();
        String assertingPartyEntityId = relyingPartyRegistration.getAssertingPartyDetails().getEntityId();
        Map<String, Object> params = new HashMap<>();
        Assertion assertion = assertionToken.getAssertion();
        if (assertionContainsInResponseTo(assertion)) {
            String requestId = getAuthnRequestId(token.getAuthenticationRequest());
            params.put(SAML2AssertionValidationParameters.SC_VALID_IN_RESPONSE_TO, requestId);
        }
        params.put(SAML2AssertionValidationParameters.COND_VALID_AUDIENCES, Collections.singleton(audience));
        params.put(SAML2AssertionValidationParameters.SC_VALID_RECIPIENTS, Collections.singleton(recipient));
        params.put(SAML2AssertionValidationParameters.VALID_ISSUERS, Collections.singleton(assertingPartyEntityId));
        paramsConsumer.accept(params);
        return new ValidationContext(params);
    }

    private static boolean assertionContainsInResponseTo(Assertion assertion) {
        if (assertion.getSubject() == null) {
            return false;
        }
        for (SubjectConfirmation confirmation : assertion.getSubject().getSubjectConfirmations()) {
            SubjectConfirmationData confirmationData = confirmation.getSubjectConfirmationData();
            if (confirmationData == null) {
                continue;
            }
            if (StringUtils.hasText(confirmationData.getInResponseTo())) {
                return true;
            }
        }
        return false;
    }

    private static String getAuthnRequestId(AbstractSaml2AuthenticationRequest serialized) {
        AuthnRequest request = parseRequest(serialized);
        if (request == null) {
            return null;
        }
        return request.getID();
    }

    private static AuthnRequest parseRequest(AbstractSaml2AuthenticationRequest request) {
        if (request == null) {
            return null;
        }
        String samlRequest = request.getSamlRequest();
        if (!StringUtils.hasText(samlRequest)) {
            return null;
        }
        if (request.getBinding() == Saml2MessageBinding.REDIRECT) {
            samlRequest = Saml2Utils.samlInflate(Saml2Utils.samlDecode(samlRequest));
        } else {
            samlRequest = new String(Saml2Utils.samlDecode(samlRequest), StandardCharsets.UTF_8);
        }
        try {
            Document document = XMLObjectProviderRegistrySupport.getParserPool()
                    .parse(new ByteArrayInputStream(samlRequest.getBytes(StandardCharsets.UTF_8)));
            Element element = document.getDocumentElement();
            return (AuthnRequest) authnRequestUnmarshaller.unmarshall(element);
        } catch (Exception ex) {
            String message = "Failed to deserialize associated authentication request [" + ex.getMessage() + "]";
            throw createAuthenticationException(Saml2ErrorCodes.MALFORMED_REQUEST_DATA, message, ex);
        }
    }

    private static Saml2AuthenticationException createAuthenticationException(String code, String message,
                                                                              Exception cause) {
        return new Saml2AuthenticationException(new Saml2Error(code, message), cause);
    }

    private static Converter<OpenSaml4AuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult> createAssertionValidator(String errorCode,
                                                                                                                                    Converter<OpenSaml4AuthenticationProvider.AssertionToken, SAML20AssertionValidator> validatorConverter,
                                                                                                                                    Converter<OpenSaml4AuthenticationProvider.AssertionToken, ValidationContext> contextConverter) {

        return (assertionToken) -> {
            Assertion assertion = assertionToken.getAssertion();
            SAML20AssertionValidator validator = validatorConverter.convert(assertionToken);
            ValidationContext context = contextConverter.convert(assertionToken);
            try {
                ValidationResult result = validator.validate(assertion, context);
                if (result == ValidationResult.VALID) {
                    return Saml2ResponseValidatorResult.success();
                }
            } catch (Exception ex) {
                String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s", assertion.getID(),
                        ((Response) assertion.getParent()).getID(), ex.getMessage());
                return Saml2ResponseValidatorResult.failure(new Saml2Error(errorCode, message));
            }
            String message = String.format("Invalid assertion [%s] for SAML response [%s]: %s", assertion.getID(),
                    ((Response) assertion.getParent()).getID(), context.getValidationFailureMessage());
            return Saml2ResponseValidatorResult.failure(new Saml2Error(errorCode, message));
        };
    }

    static SAML20AssertionValidator createSignatureValidator(SignatureTrustEngine engine) {
        return new SAML20AssertionValidator(new ArrayList<>(), new ArrayList<>(), new ArrayList<>(), engine,
                validator) {
            @Nonnull
            @Override
            protected ValidationResult validateConditions(Assertion assertion, ValidationContext context) {
                return ValidationResult.VALID;
            }

            @Nonnull
            @Override
            protected ValidationResult validateSubjectConfirmation(Assertion assertion, ValidationContext context) {
                return ValidationResult.VALID;
            }

            @Nonnull
            @Override
            protected ValidationResult validateStatements(Assertion assertion, ValidationContext context) {
                return ValidationResult.VALID;
            }

            @Override
            protected ValidationResult validateIssuer(Assertion assertion, ValidationContext context) {
                return ValidationResult.VALID;
            }
        };

    }
}
