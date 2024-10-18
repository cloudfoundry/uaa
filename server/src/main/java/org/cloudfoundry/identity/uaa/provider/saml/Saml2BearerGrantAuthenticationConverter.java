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

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.cloudfoundry.identity.uaa.authentication.BackwardsCompatibleTokenEndpointAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.UaaSamlPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
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
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Condition;
import org.opensaml.saml.saml2.core.OneTimeUse;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.core.impl.AssertionUnmarshaller;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.xmlsec.signature.support.SignaturePrevalidator;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.convert.converter.Converter;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationException;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.Assert;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.NotANumber;

/**
 * This {@link AuthenticationConverter} is used in the SAML2 Bearer Grant exchange in {@link BackwardsCompatibleTokenEndpointAuthenticationFilter}
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc7522">RFC 7522</a>
 */
@Slf4j
public final class Saml2BearerGrantAuthenticationConverter implements AuthenticationConverter,
        ApplicationEventPublisherAware {

    static {
        OpenSamlInitializationService.initialize();
    }

    private static final UnaryOperator<String> assertionConsumerServiceLocationMutationFunction = o -> o.replace("/saml/SSO/alias/", "/oauth/token/alias/");

    private static final AssertionUnmarshaller assertionUnmarshaller;

    private static final ParserPool parserPool;

    static {
        XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
        assertionUnmarshaller = (AssertionUnmarshaller) registry.getUnmarshallerFactory()
                .getUnmarshaller(Assertion.DEFAULT_ELEMENT_NAME);
        parserPool = registry.getParserPool();
    }

    private final Converter<AssertionToken, Saml2ResponseValidatorResult> assertionSignatureValidator = createDefaultAssertionSignatureValidator();

    private final Consumer<AssertionToken> assertionElementsDecrypter = createDefaultAssertionElementsDecrypter();

    private final Converter<AssertionToken, Saml2ResponseValidatorResult> assertionValidator = createDefaultAssertionValidator();

    private final Converter<AssertionToken, ? extends AbstractAuthenticationToken> assertionTokenAuthenticationConverter = createDefaultAssertionAuthenticationConverter();

    private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;
    private final IdentityZoneManager identityZoneManager;
    private final IdentityProviderProvisioning identityProviderProvisioning;
    private final SamlUaaAuthenticationUserManager userManager;
    private ApplicationEventPublisher eventPublisher;

    /**
     * Creates an {@link Saml2BearerGrantAuthenticationConverter}
     */
    public Saml2BearerGrantAuthenticationConverter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
                                                   IdentityZoneManager identityZoneManager,
                                                   IdentityProviderProvisioning identityProviderProvisioning,
                                                   SamlUaaAuthenticationUserManager userManager,
                                                   ApplicationEventPublisher eventPublisher) {

        Assert.notNull(relyingPartyRegistrationResolver, "relyingPartyRegistrationResolver cannot be null");
        this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
        this.identityZoneManager = identityZoneManager;
        this.identityProviderProvisioning = identityProviderProvisioning;
        this.userManager = userManager;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Construct a default strategy for validating each SAML 2.0 Assertion and associated
     * {@link Authentication} token
     *
     * @return the default assertion validator strategy
     */
    public static Converter<AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionValidator() {

        return createDefaultAssertionValidatorWithParameters(
                params -> params.put(SAML2AssertionValidationParameters.CLOCK_SKEW, Duration.ofMinutes(5)));
    }

    /**
     * Construct a default strategy for converting a SAML 2.0 Assertion and
     * {@link Authentication} token into a {@link Saml2Authentication}
     *
     * @return the default response authentication converter strategy
     */
    private Converter<AssertionToken, ? extends AbstractAuthenticationToken> createDefaultAssertionAuthenticationConverter() {
        return assertionToken -> {
            Assertion assertion = assertionToken.assertion;
            Saml2AuthenticationToken token = assertionToken.token;
            String username = assertion.getSubject().getNameID().getValue();
            Map<String, List<Object>> attributes = getAssertionAttributes(assertion);
            List<String> sessionIndexes = getSessionIndexes(assertion);
            DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal(username, attributes,
                    sessionIndexes);
            String registrationId = assertionToken.token.getRelyingPartyRegistration().getRegistrationId();
            principal.setRelyingPartyRegistrationId(registrationId);
            return new Saml2Authentication(principal, token.getSaml2Response(),
                    AuthorityUtils.createAuthorityList("ROLE_USER"));
        };
    }

    /**
     * Construct a default strategy for validating each SAML 2.0 Assertion and associated
     * {@link Authentication} token
     *
     * @param validationContextParameters a consumer for editing the values passed to the
     *                                    {@link ValidationContext} for each assertion being validated
     * @return the default assertion validator strategy
     * @since 5.8
     */
    public static Converter<AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionValidatorWithParameters(
            Consumer<Map<String, Object>> validationContextParameters) {
        return createAssertionValidator(Saml2ErrorCodes.INVALID_ASSERTION,
                assertionToken -> SAML20AssertionValidators.attributeValidator,
                assertionToken -> createValidationContext(assertionToken, validationContextParameters));
    }

    @Override
    public Authentication convert(HttpServletRequest request) throws AuthenticationException {
        RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationResolver.resolve(request, null);

        String serializedAssertion = request.getParameter("assertion");
        byte[] decodedAssertion = Saml2Utils.samlDecode(serializedAssertion);
        String assertionXml = new String(decodedAssertion, StandardCharsets.UTF_8);

        Assertion assertion = parseAssertion(assertionXml);
        Saml2AuthenticationToken authenticationToken = new Saml2AuthenticationToken(relyingPartyRegistration, assertionXml);
        process(authenticationToken, assertion);

        String subjectName = assertion.getSubject().getNameID().getValue();
        String alias = relyingPartyRegistration.getRegistrationId();
        IdentityZone zone = identityZoneManager.getCurrentIdentityZone();

        UaaPrincipal initialPrincipal = new UaaPrincipal(NotANumber, subjectName, subjectName,
                alias, subjectName, zone.getId());

        boolean addNew;
        IdentityProvider<SamlIdentityProviderDefinition> idp;
        SamlIdentityProviderDefinition samlConfig;
        try {
            idp = identityProviderProvisioning.retrieveByOrigin(alias, identityZoneManager.getCurrentIdentityZoneId());
            samlConfig = idp.getConfig();
            addNew = samlConfig.isAddShadowUserOnLogin();
            if (!idp.isActive()) {
                throw new ProviderNotFoundException("Identity Provider has been disabled by administrator for alias:" + alias);
            }
        } catch (EmptyResultDataAccessException x) {
            throw new ProviderNotFoundException("No SAML identity provider found in zone for alias:" + alias);
        }

        MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();

        log.debug("Mapped SAML authentication to IDP with origin '{}' and username '{}'",
                idp.getOriginKey(), initialPrincipal.getName());

        UaaUser user = userManager.createIfMissing(initialPrincipal, addNew, List.of(), userAttributes);
        UaaAuthentication authentication = new UaaAuthentication(
                new UaaSamlPrincipal(user),
                authenticationToken.getCredentials(),
                user.getAuthorities(),
                Set.of(),
                userAttributes,
                null,
                true, System.currentTimeMillis(),
                -1);
        authentication.setAuthenticationMethods(Set.of("ext"));
        setAuthContextClassRefs(assertion, authentication);

        publish(new IdentityProviderAuthenticationSuccessEvent(user, authentication, OriginKeys.SAML, identityZoneManager.getCurrentIdentityZoneId()));

        AbstractSaml2AuthenticationRequest authenticationRequest = authenticationToken.getAuthenticationRequest();
        if (authenticationRequest != null) {
            String relayState = authenticationRequest.getRelayState();
            configureRelayRedirect(relayState);
        }

        return authentication;
    }

    private static void setAuthContextClassRefs(Assertion assertion, UaaAuthentication authentication) {
        Set<String> authContextClassRef = new HashSet<>();
        assertion.getAuthnStatements().forEach(authnStatement -> {
            if (authnStatement.getAuthnContext() != null) {
                authContextClassRef.add(authnStatement.getAuthnContext().getAuthnContextClassRef().getURI());
            }
        });
        authentication.setAuthContextClassRef(authContextClassRef);
    }

    public void configureRelayRedirect(String relayState) {
        //configure relay state
        if (UaaUrlUtils.isUrl(relayState)) {
            RequestContextHolder.currentRequestAttributes()
                    .setAttribute(
                            UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE,
                            relayState,
                            RequestAttributes.SCOPE_REQUEST
                    );
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher;
    }

    private void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    /**
     * @param authentication the authentication request object must be of type
     *                       {@link Saml2AuthenticationToken}
     * @return {@link Saml2Authentication} if the assertion is valid
     * @throws AuthenticationException if a validation exception occurs
     */
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            Saml2AuthenticationToken token = (Saml2AuthenticationToken) authentication;
            String serializedAssertion = token.getSaml2Response();
            Assertion assertion = parseAssertion(serializedAssertion);
            process(token, assertion);
            AbstractAuthenticationToken authenticationResponse = this.assertionTokenAuthenticationConverter
                    .convert(new AssertionToken(assertion, token));
            if (authenticationResponse != null) {
                authenticationResponse.setDetails(authentication.getDetails());
            }
            return authenticationResponse;
        } catch (Saml2AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw createAuthenticationException(Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR, ex.getMessage(), ex);
        }
    }

    private static Assertion parseAssertion(String assertion) throws Saml2Exception, Saml2AuthenticationException {
        try {
            Document document = parserPool
                    .parse(new ByteArrayInputStream(assertion.getBytes(StandardCharsets.UTF_8)));
            Element element = document.getDocumentElement();
            return (Assertion) assertionUnmarshaller.unmarshall(element);
        } catch (Exception ex) {
            throw createAuthenticationException(Saml2ErrorCodes.INVALID_ASSERTION, ex.getMessage(), ex);
        }
    }

    private void process(Saml2AuthenticationToken token, Assertion assertion) {
        String issuer = assertion.getIssuer().getValue();
        log.debug("Processing SAML response from {}", issuer);

        AssertionToken assertionToken = new AssertionToken(assertion, token);
        Saml2ResponseValidatorResult result = this.assertionSignatureValidator.convert(assertionToken);
        if (assertion.isSigned()) {
            this.assertionElementsDecrypter.accept(new AssertionToken(assertion, token));
        }
        result = result.concat(this.assertionValidator.convert(assertionToken));

        if (!hasName(assertion)) {
            Saml2Error error = new Saml2Error(Saml2ErrorCodes.SUBJECT_NOT_FOUND,
                    "Assertion [" + assertion.getID() + "] is missing a subject");
            result = result.concat(error);
        }

        if (result.hasErrors()) {
            Collection<Saml2Error> errors = result.getErrors();
            if (log.isTraceEnabled()) {
                log.trace("Found {} validation errors in SAML assertion [{}}]: {}", errors.size(), assertion.getID(), errors);
            } else if (log.isDebugEnabled()) {
                log.debug("Found {} validation errors in SAML assertion [{}}]", errors.size(), assertion.getID());
            }
            Saml2Error first = errors.iterator().next();
            throw createAuthenticationException(first.getErrorCode(), first.getDescription(), null);
        } else {
            log.debug("Successfully processed SAML Assertion [{}]", assertion.getID());
        }
    }

    private Converter<AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionSignatureValidator() {
        return createAssertionValidator(Saml2ErrorCodes.INVALID_SIGNATURE, assertionToken -> {
            RelyingPartyRegistration registration = assertionToken.getToken().getRelyingPartyRegistration();
            SignatureTrustEngine engine = OpenSamlVerificationUtils.trustEngine(registration);
            return SAML20AssertionValidators.createSignatureValidator(engine);
        }, assertionToken -> new ValidationContext(
                Collections.singletonMap(SAML2AssertionValidationParameters.SIGNATURE_REQUIRED, false)));
    }

    private Consumer<AssertionToken> createDefaultAssertionElementsDecrypter() {
        return assertionToken -> {
            Assertion assertion = assertionToken.getAssertion();
            RelyingPartyRegistration registration = assertionToken.getToken().getRelyingPartyRegistration();
            try {
                OpenSamlDecryptionUtils.decryptAssertionElements(assertion, registration);
            } catch (Exception ex) {
                throw createAuthenticationException(Saml2ErrorCodes.DECRYPTION_ERROR, ex.getMessage(), ex);
            }
        };
    }

    private boolean hasName(Assertion assertion) {
        if (assertion == null) {
            return false;
        }
        if (assertion.getSubject() == null) {
            return false;
        }
        if (assertion.getSubject().getNameID() == null) {
            return false;
        }
        return assertion.getSubject().getNameID().getValue() != null;
    }

    private static Map<String, List<Object>> getAssertionAttributes(Assertion assertion) {
        MultiValueMap<String, Object> attributeMap = new LinkedMultiValueMap<>();
        for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
            for (Attribute attribute : attributeStatement.getAttributes()) {
                List<Object> attributeValues = new ArrayList<>();
                for (XMLObject xmlObject : attribute.getAttributeValues()) {
                    Object attributeValue = getXmlObjectValue(xmlObject);
                    if (attributeValue != null) {
                        attributeValues.add(attributeValue);
                    }
                }
                attributeMap.addAll(attribute.getName(), attributeValues);
            }
        }
        return new LinkedHashMap<>(attributeMap); // gh-11785
    }

    private static List<String> getSessionIndexes(Assertion assertion) {
        List<String> sessionIndexes = new ArrayList<>();
        for (AuthnStatement statement : assertion.getAuthnStatements()) {
            sessionIndexes.add(statement.getSessionIndex());
        }
        return sessionIndexes;
    }

    private static Object getXmlObjectValue(XMLObject xmlObject) {
        if (xmlObject instanceof XSAny xsAny) {
            return xsAny.getTextContent();
        }
        if (xmlObject instanceof XSString xsstring) {
            return xsstring.getValue();
        }
        if (xmlObject instanceof XSInteger xsInteger) {
            return xsInteger.getValue();
        }
        if (xmlObject instanceof XSURI xsUri) {
            return xsUri.getURI();
        }
        if (xmlObject instanceof XSBoolean xsBoolean) {
            XSBooleanValue xsBooleanValue = xsBoolean.getValue();
            return (xsBooleanValue != null) ? xsBooleanValue.getValue() : null;
        }
        if (xmlObject instanceof XSDateTime xsDateTime) {
            return xsDateTime.getValue();
        }
        return xmlObject;
    }

    private static Saml2AuthenticationException createAuthenticationException(String code, String message,
                                                                              Exception cause) {
        return new Saml2AuthenticationException(new Saml2Error(code, message), cause);
    }

    private static Converter<AssertionToken, Saml2ResponseValidatorResult> createAssertionValidator(String errorCode,
                                                                                                    Converter<AssertionToken, SAML20AssertionValidator> validatorConverter,
                                                                                                    Converter<AssertionToken, ValidationContext> contextConverter) {

        return assertionToken -> {
            Assertion assertion = assertionToken.assertion;
            SAML20AssertionValidator validator = validatorConverter.convert(assertionToken);
            ValidationContext context = contextConverter.convert(assertionToken);
            try {
                ValidationResult result = validator.validate(assertion, context);
                if (result == ValidationResult.VALID) {
                    return Saml2ResponseValidatorResult.success();
                }
            } catch (Exception ex) {
                String message = String.format("Invalid assertion [%s]: %s", assertion.getID(), ex.getMessage());
                return Saml2ResponseValidatorResult.failure(new Saml2Error(errorCode, message));
            }
            String message = String.format("Invalid assertion [%s]: %s", assertion.getID(), context.getValidationFailureMessage());
            return Saml2ResponseValidatorResult.failure(new Saml2Error(errorCode, message));
        };
    }

    private static ValidationContext createValidationContext(AssertionToken assertionToken,
                                                             Consumer<Map<String, Object>> paramsConsumer) {
        Saml2AuthenticationToken token = assertionToken.token;
        RelyingPartyRegistration relyingPartyRegistration = token.getRelyingPartyRegistration();

        String audience = relyingPartyRegistration.getRegistrationId();
        String recipient = assertionConsumerServiceLocationMutationFunction.apply(relyingPartyRegistration.getAssertionConsumerServiceLocation());

        String assertingPartyEntityId = relyingPartyRegistration.getAssertingPartyDetails().getEntityId();
        Map<String, Object> params = new HashMap<>();
        Assertion assertion = assertionToken.getAssertion();
        if (assertionContainsInResponseTo(assertion)) {
            String requestId = assertionToken.getAssertionId();
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

    private static class SAML20AssertionValidators {

        private static final Collection<ConditionValidator> conditions = new ArrayList<>();

        private static final Collection<SubjectConfirmationValidator> subjects = new ArrayList<>();

        private static final Collection<StatementValidator> statements = new ArrayList<>();

        private static final SignaturePrevalidator validator = new SAMLSignatureProfileValidator();

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

        private static final SAML20AssertionValidator attributeValidator = new SAML20AssertionValidator(conditions,
                subjects, statements, null, null) {
            @Nonnull
            @Override
            protected ValidationResult validateSignature(Assertion token, ValidationContext context) {
                return ValidationResult.VALID;
            }
        };

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

    /**
     * A tuple containing an OpenSAML {@link Assertion} and its associated authentication
     * token.
     *
     * @since 5.4
     */
    @Getter
    public static class AssertionToken {

        private final Saml2AuthenticationToken token;

        private final Assertion assertion;

        AssertionToken(Assertion assertion, Saml2AuthenticationToken token) {
            this.token = token;
            this.assertion = assertion;
        }

        public String getAssertionId() {
            return this.assertion.getID();
        }
    }
}
