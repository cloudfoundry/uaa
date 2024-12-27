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

import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.cloudfoundry.identity.uaa.authentication.BackwardsCompatibleTokenEndpointAuthenticationFilter;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.UaaSamlPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.common.assertion.ValidationContext;
import org.opensaml.saml.saml2.assertion.SAML2AssertionValidationParameters;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.AssertionUnmarshaller;
import org.opensaml.saml.saml2.core.impl.ResponseUnmarshaller;
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
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Consumer;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.NotANumber;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.SAML;
import static org.cloudfoundry.identity.uaa.provider.saml.OpenSaml4AuthenticationProvider.createDefaultAssertionValidatorWithParameters;

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

    private static final AssertionUnmarshaller assertionUnmarshaller;
    private static final ResponseUnmarshaller responseUnMarshaller;

    private static final ParserPool parserPool;

    static {
        XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
        assertionUnmarshaller = (AssertionUnmarshaller) registry.getUnmarshallerFactory()
                .getUnmarshaller(Assertion.DEFAULT_ELEMENT_NAME);
        responseUnMarshaller = (ResponseUnmarshaller) registry.getUnmarshallerFactory()
                .getUnmarshaller(Response.DEFAULT_ELEMENT_NAME);
        parserPool = registry.getParserPool();
    }

    private final Converter<OpenSaml4AuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult> assertionSignatureValidator = OpenSaml4AuthenticationProvider.createDefaultAssertionSignatureValidator();

    private final Consumer<OpenSaml4AuthenticationProvider.AssertionToken> assertionElementsDecrypter = OpenSaml4AuthenticationProvider.createDefaultAssertionElementsDecrypter();

    private final Converter<OpenSaml4AuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult> assertionValidator = createDefaultAssertionValidator();

    private final Converter<OpenSaml4AuthenticationProvider.AssertionToken, AbstractAuthenticationToken> assertionTokenAuthenticationConverter = createDefaultAssertionAuthenticationConverter();

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
    public static Converter<OpenSaml4AuthenticationProvider.AssertionToken, Saml2ResponseValidatorResult> createDefaultAssertionValidator() {

        return createDefaultAssertionValidatorWithParameters(
                params -> params.put(SAML2AssertionValidationParameters.CLOCK_SKEW, Duration.ofMinutes(5)), true);
    }

    /**
     * Construct a default strategy for converting a SAML 2.0 Assertion and
     * {@link Authentication} token into a {@link Saml2Authentication}
     *
     * @return the default response authentication converter strategy
     */
    static Converter<OpenSaml4AuthenticationProvider.AssertionToken, AbstractAuthenticationToken> createDefaultAssertionAuthenticationConverter() {
        return assertionToken -> {
            Assertion assertion = assertionToken.getAssertion();
            Saml2AuthenticationToken token = assertionToken.getToken();
            String username = assertion.getSubject().getNameID().getValue();
            Map<String, List<Object>> attributes = OpenSaml4AuthenticationProvider.getAssertionAttributes(assertion);
            List<String> sessionIndexes = OpenSaml4AuthenticationProvider.getSessionIndexes(assertion);
            DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal(username, attributes,
                    sessionIndexes);
            String registrationId = token.getRelyingPartyRegistration().getRegistrationId();
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

    @Override
    public Authentication convert(HttpServletRequest request) throws AuthenticationException {

        String serializedAssertion = request.getParameter("assertion");
        byte[] decodedAssertion = Saml2Utils.samlBearerDecode(serializedAssertion);
        String assertionXml = new String(decodedAssertion, StandardCharsets.UTF_8);

        Assertion assertion = parseAssertion(assertionXml);
        RelyingPartyRegistration relyingPartyRegistration = relyingPartyRegistrationResolver.resolve(request, getIssuer(assertion));
        IdentityProvider<SamlIdentityProviderDefinition> idp = retrieveSamlIdpSamlIdentityProvider(relyingPartyRegistration.getRegistrationId());
        Saml2AuthenticationToken authenticationToken = new Saml2AuthenticationToken(relyingPartyRegistration, assertionXml);
        process(authenticationToken, assertion);

        String subjectName = assertion.getSubject().getNameID().getValue();
        String alias = idp.getOriginKey();
        IdentityZone zone = identityZoneManager.getCurrentIdentityZone();

        UaaPrincipal initialPrincipal = new UaaPrincipal(NotANumber, subjectName, subjectName,
                alias, subjectName, zone.getId());

        SamlIdentityProviderDefinition samlConfig = idp.getConfig();
        boolean addNew = samlConfig.isAddShadowUserOnLogin();

        MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();

        log.debug("Mapped SAML authentication to IDP with origin '{}' and username '{}'",
                idp.getOriginKey(), initialPrincipal.getName());

        UaaUser user = userManager.createIfMissing(initialPrincipal, addNew, List.of(), userAttributes);
        UaaAuthentication authentication = new UaaAuthentication(
                new UaaSamlPrincipal(user, null),
                authenticationToken.getCredentials(),
                user.getAuthorities(),
                Set.of(),
                userAttributes,
                null,
                true, System.currentTimeMillis(),
                -1);
        authentication.setAuthenticationMethods(Set.of("ext"));
        setAuthContextClassRefs(assertion, authentication);

        publish(new IdentityProviderAuthenticationSuccessEvent(user, authentication, SAML, identityZoneManager.getCurrentIdentityZoneId()));

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
                    .convert(new OpenSaml4AuthenticationProvider.AssertionToken(assertion, token));
            if (authenticationResponse != null) {
                authenticationResponse.setDetails(authentication.getDetails());
            }
            return authenticationResponse;
        } catch (Saml2AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw OpenSaml4AuthenticationProvider.createAuthenticationException(Saml2ErrorCodes.INTERNAL_VALIDATION_ERROR, ex.getMessage(), ex);
        }
    }

    private static Assertion parseAssertion(String assertion) throws Saml2Exception, Saml2AuthenticationException {
        try {
            Document document = parserPool
                    .parse(new ByteArrayInputStream(assertion.getBytes(StandardCharsets.UTF_8)));
            Element element = document.getDocumentElement();
            return (Assertion) assertionUnmarshaller.unmarshall(element);
        } catch (Exception ex) {
            throw OpenSaml4AuthenticationProvider.createAuthenticationException(Saml2ErrorCodes.INVALID_ASSERTION, "Unable to parse bearer assertion", ex);
        }
    }

    protected static Response parseSamlResponse(String samlResponse) throws Saml2Exception, Saml2AuthenticationException {
        try {
            Document document = parserPool
                    .parse(new ByteArrayInputStream(samlResponse.getBytes(StandardCharsets.UTF_8)));
            Element element = document.getDocumentElement();
            return (Response) responseUnMarshaller.unmarshall(element);
        } catch (Exception ex) {
            throw OpenSaml4AuthenticationProvider.createAuthenticationException(Saml2ErrorCodes.INVALID_RESPONSE, "Unable to parse saml response", ex);
        }
    }

    protected static String getIssuer(Response response) {
        return Optional.ofNullable(response.getIssuer()).map(Issuer::getValue)
                .orElseThrow(() -> new Saml2AuthenticationException(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Missing issuer in saml response")));
    }

    private static String getIssuer(Assertion assertion) {
        return Optional.ofNullable(assertion.getIssuer()).map(Issuer::getValue)
                .orElseThrow(() -> new Saml2AuthenticationException(new Saml2Error(Saml2ErrorCodes.INVALID_ASSERTION, "Missing issuer in bearer assertion")));
    }

    private void process(Saml2AuthenticationToken token, Assertion assertion) {
        String issuer = getIssuer(assertion);
        log.debug("Processing SAML response from {}", issuer);

        OpenSaml4AuthenticationProvider.AssertionToken assertionToken = new OpenSaml4AuthenticationProvider.AssertionToken(assertion, token);
        Saml2ResponseValidatorResult result = this.assertionSignatureValidator.convert(assertionToken);
        if (assertion.isSigned()) {
            this.assertionElementsDecrypter.accept(new OpenSaml4AuthenticationProvider.AssertionToken(assertion, token));
        }
        result = result.concat(this.assertionValidator.convert(assertionToken));

        if (!OpenSaml4AuthenticationProvider.hasName(assertion)) {
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
            throw OpenSaml4AuthenticationProvider.createAuthenticationException(first.getErrorCode(), first.getDescription(), null);
        } else {
            log.debug("Successfully processed SAML Assertion [{}]", assertion.getID());
        }
    }

    private IdentityProvider<SamlIdentityProviderDefinition> retrieveSamlIdpSamlIdentityProvider(String origin) {
        try {
            IdentityProvider<SamlIdentityProviderDefinition> idp = identityProviderProvisioning.retrieveByOrigin(origin,
                    identityZoneManager.getCurrentIdentityZoneId());
            if (idp == null || !SAML.equals(idp.getType()) || !idp.isActive()) {
                throw new ProviderNotFoundException("Identity Provider has been disabled by administrator for alias: " + origin);
            }
            return idp;
        } catch (EmptyResultDataAccessException x) {
            throw new ProviderNotFoundException("No SAML identity provider found in zone for alias: " + origin);
        }
    }
}
