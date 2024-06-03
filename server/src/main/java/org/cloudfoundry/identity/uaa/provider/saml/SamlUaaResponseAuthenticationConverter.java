package org.cloudfoundry.identity.uaa.provider.saml;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSQName;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Response;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.core.convert.converter.Converter;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml4AuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationToken;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import javax.xml.namespace.QName;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.NotANumber;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_VERIFIED_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.isAcceptedInvitationAuthentication;

/**
 *
 */
@Slf4j
public class SamlUaaResponseAuthenticationConverter
        implements Converter<OpenSaml4AuthenticationProvider.ResponseToken, UaaAuthentication>,
        ApplicationEventPublisherAware {

    public static final String AUTHENTICATION_CONTEXT_CLASS_REFERENCE = "acr";

    private final IdentityZoneManager identityZoneManager;

    //private static final AuthnRequestUnmarshaller authnRequestUnmarshaller;
    private final UaaUserDatabase userDatabase;
    private final IdentityProviderProvisioning identityProviderProvisioning;

    //private static final ParserPool parserPool;

    //private static final ResponseUnmarshaller responseUnmarshaller;

    //    private final ScimGroupExternalMembershipManager externalMembershipManager;
    private ApplicationEventPublisher eventPublisher;

    public SamlUaaResponseAuthenticationConverter(IdentityZoneManager identityZoneManager,
                                                  final UaaUserDatabase userDatabase,
                                                  final JdbcIdentityProviderProvisioning identityProviderProvisioning) {
        this.identityZoneManager = identityZoneManager;
        this.userDatabase = userDatabase;
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    @Override
    public UaaAuthentication convert(OpenSaml4AuthenticationProvider.ResponseToken responseToken) {
        // Do the default conversion
        Saml2Authentication authentication = OpenSaml4AuthenticationProvider
                .createDefaultResponseAuthenticationConverter()
                .convert(responseToken);

        Saml2AuthenticationToken authenticationToken = responseToken.getToken();
        Response response = responseToken.getResponse();

        IdentityZone zone = identityZoneManager.getCurrentIdentityZone();
        log.debug(String.format("Initiating SAML authentication in zone '%s' domain '%s'",
                zone.getId(), zone.getSubdomain()));
        RelyingPartyRegistration relyingPartyRegistration = authenticationToken.getRelyingPartyRegistration();
        AbstractSaml2AuthenticationRequest authenticationRequest = authenticationToken.getAuthenticationRequest();

        Assertion assertion = responseToken.getResponse().getAssertions().get(0);
        String username = assertion.getSubject().getNameID().getValue();
        //UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

        List<? extends GrantedAuthority> samlAuthorities = List.copyOf(authenticationToken.getAuthorities());

        LinkedMultiValueMap<String, String> customAttributes = new LinkedMultiValueMap<>();
//        for (Map.Entry<String, List<String>> entry : userAttributes.entrySet()) {
//            if (entry.getKey().startsWith(USER_ATTRIBUTE_PREFIX)) {
//                customAttributes.put(entry.getKey().substring(USER_ATTRIBUTE_PREFIX.length()), entry.getValue());
//            }
//        }

        Set<String> externalGroups = Set.of();
        boolean authenticated = true;
        long authenticatedTime = System.currentTimeMillis();
        long expiresAt = -1;

        UaaPrincipal initialPrincipal = new UaaPrincipal(NotANumber, "marissa@test.org", authenticationToken.getName(),
                relyingPartyRegistration.getRegistrationId(), authenticationToken.getName(), zone.getId());
        UaaAuthentication initialUaaAuthentication = new UaaAuthentication(initialPrincipal,
                authenticationToken.getCredentials(), samlAuthorities, externalGroups, customAttributes, null,
                authenticated, authenticatedTime,
                expiresAt);


        String alias = relyingPartyRegistration.getRegistrationId();
//        String relayState = context.getRelayState();
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
//
        log.debug(
                String.format(
                        "Mapped SAML authentication to IDP with origin '%s' and username '%s'",
                        idp.getOriginKey(),
                        initialPrincipal.getName()
                )
        );


        //Collection<? extends GrantedAuthority> samlAuthorities = retrieveSamlAuthorities(samlConfig, (SAMLCredential) result.getCredentials());
//
//        Collection<? extends GrantedAuthority> authorities =
        // Collection<? extends GrantedAuthority> samlAuthoritinull;
//        SamlIdentityProviderDefinition.ExternalGroupMappingMode groupMappingMode = idp.getConfig().getGroupMappingMode();
//        switch (groupMappingMode) {
//            case EXPLICITLY_MAPPED:
//                authorities = mapAuthorities(idp.getOriginKey(), samlAuthorities);
//                break;
//            case AS_SCOPES:
//                authorities = new LinkedList<>(samlAuthorities);
//                break;
//        }
//
//        Set<String> filteredExternalGroups = filterSamlAuthorities(samlConfig, samlAuthorities);
        initialUaaAuthentication.setAuthenticationMethods(Set.of("ext"));
        MultiValueMap<String, String> userAttributes = retrieveUserAttributes(samlConfig, response);
        List<String> acrValues = userAttributes.get(AUTHENTICATION_CONTEXT_CLASS_REFERENCE);
        if (acrValues != null) {
            initialUaaAuthentication.setAuthContextClassRef(Set.copyOf(acrValues));
        }

//
//        if (samlConfig.getAuthnContext() != null) {
//            if (Collections.disjoint(userAttributes.get(AUTHENTICATION_CONTEXT_CLASS_REFERENCE), samlConfig.getAuthnContext())) {
//                throw new BadCredentialsException("Identity Provider did not authenticate with the requested AuthnContext.");
//            }
//        }
//
        UaaUser user = createIfMissing(initialPrincipal, addNew, samlAuthorities, userAttributes);
        UaaPrincipal newPrincipal = new UaaPrincipal(user);
        UaaAuthentication newAuthentication = new UaaAuthentication(initialUaaAuthentication, newPrincipal);

        // publish(new IdentityProviderAuthenticationSuccessEvent(user, newAuthentication, OriginKeys.SAML, identityZoneManager.getCurrentIdentityZoneId()));
//        if (samlConfig.isStoreCustomAttributes()) {
//            userDatabase.storeUserInfo(user.getId(),
//                    new UserInfo()
//                            .setUserAttributes(resultUaaAuthentication.getUserAttributes())
//                            .setRoles(new LinkedList(resultUaaAuthentication.getExternalGroups()))
//            );
//        }
//        configureRelayRedirect(relayState);
//
        return newAuthentication;
    }

    /**
     * Default conversion:
     * Response response = responseToken.response;
     * Saml2AuthenticationToken token = responseToken.token;
     * Assertion assertion = CollectionUtils.firstElement(response.getAssertions());
     * String username = assertion.getSubject().getNameID().getValue();
     * Map<String, List<Object>> attributes = getAssertionAttributes(assertion);
     * List<String> sessionIndexes = getSessionIndexes(assertion);
     * DefaultSaml2AuthenticatedPrincipal principal = new DefaultSaml2AuthenticatedPrincipal(username, attributes,
     * sessionIndexes);
     * String registrationId = responseToken.token.getRelyingPartyRegistration().getRegistrationId();
     * principal.setRelyingPartyRegistrationId(registrationId);
     * return new Saml2Authentication(principal, token.getSaml2Response(),
     * AuthorityUtils.createAuthorityList("ROLE_USER"));
     */

    /*
     * TODO: Move User Attributes Stuff
     */
    public MultiValueMap<String, String> retrieveUserAttributes(SamlIdentityProviderDefinition definition, Response response) {
        log.debug(String.format("Retrieving SAML user attributes [zone:%s, origin:%s]", definition.getZoneId(), definition.getIdpEntityAlias()));
        MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
        List<Assertion> assertions = response.getAssertions();
        if (assertions.isEmpty()) {
            return userAttributes;
        }
        for (Assertion assertion : assertions) {
            if (assertion.getAttributeStatements() != null) {
                for (AttributeStatement statement : assertion.getAttributeStatements()) {
                    for (Attribute attribute : statement.getAttributes()) {
                        if (attribute.getAttributeValues() != null) {
                            for (XMLObject xmlObject : attribute.getAttributeValues()) {
                                String key = attribute.getName();
                                String value = getStringValue(key, definition, xmlObject);
                                if (value != null) {
                                    userAttributes.add(key, value);
                                }
                            }
                        }
                    }
                }
            }
        }

        if (definition != null && definition.getAttributeMappings() != null) {
            for (Map.Entry<String, Object> attributeMapping : definition.getAttributeMappings().entrySet()) {
                Object attributeKey = attributeMapping.getValue();
                if (attributeKey instanceof String) {
                    if (userAttributes.get(attributeKey) != null) {
                        String key = attributeMapping.getKey();
                        userAttributes.addAll(key, userAttributes.get(attributeKey));
                    }
                }
            }
        }
//        if (credential.getAuthenticationAssertion() != null && credential.getAuthenticationAssertion().getAuthnStatements() != null) {
//            for (AuthnStatement statement : credential.getAuthenticationAssertion().getAuthnStatements()) {
//                if (statement.getAuthnContext() != null && statement.getAuthnContext().getAuthnContextClassRef() != null) {
//                    userAttributes.add(AUTHENTICATION_CONTEXT_CLASS_REFERENCE, statement.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
//                }
//            }
//        }
        return userAttributes;
    }

    protected String getStringValue(String key, SamlIdentityProviderDefinition definition, XMLObject xmlObject) {
        String value = null;
        if (xmlObject instanceof XSString) {
            value = ((XSString) xmlObject).getValue();
        } else if (xmlObject instanceof XSAny) {
            value = ((XSAny) xmlObject).getTextContent();
        } else if (xmlObject instanceof XSInteger) {
            Integer i = ((XSInteger) xmlObject).getValue();
            value = i != null ? i.toString() : null;
        } else if (xmlObject instanceof XSBoolean) {
            XSBooleanValue b = ((XSBoolean) xmlObject).getValue();
            value = b != null && b.getValue() != null ? b.getValue().toString() : null;
        } else if (xmlObject instanceof XSDateTime) {
            Instant d = ((XSDateTime) xmlObject).getValue();
            value = d != null ? d.toString() : null;
        } else if (xmlObject instanceof XSQName) {
            QName name = ((XSQName) xmlObject).getValue();
            value = name != null ? name.toString() : null;
        } else if (xmlObject instanceof XSURI) {
            value = ((XSURI) xmlObject).getURI();
        } else if (xmlObject instanceof XSBase64Binary) {
            value = ((XSBase64Binary) xmlObject).getValue();
        }

        if (value != null) {
            log.debug(String.format("Found SAML user attribute %s of value %s [zone:%s, origin:%s]", key, value, definition.getZoneId(), definition.getIdpEntityAlias()));
            return value;
        } else if (xmlObject != null) {
            log.debug(String.format("SAML user attribute %s at is not of type XSString or other recognizable type, %s [zone:%s, origin:%s]", key, xmlObject.getClass().getName(), definition.getZoneId(), definition.getIdpEntityAlias()));
        }
        return null;
    }

    /*
     * TODO: Move User Creation Stuff
     */

    protected UaaUser createIfMissing(UaaPrincipal samlPrincipal, boolean addNew, Collection<? extends GrantedAuthority> authorities, MultiValueMap<String, String> userAttributes) {
        UaaUser user = null;
        String invitedUserId = null;
        boolean is_invitation_acceptance = isAcceptedInvitationAuthentication();
        if (is_invitation_acceptance) {
            invitedUserId = (String) RequestContextHolder.currentRequestAttributes().getAttribute("user_id", RequestAttributes.SCOPE_SESSION);
            user = userDatabase.retrieveUserById(invitedUserId);
            if (userAttributes.getFirst(EMAIL_ATTRIBUTE_NAME) != null) {
                if (!userAttributes.getFirst(EMAIL_ATTRIBUTE_NAME).equalsIgnoreCase(user.getEmail())) {
                    throw new BadCredentialsException("SAML User email mismatch. Authenticated email doesn't match invited email.");
                }
            } else {
                userAttributes = new LinkedMultiValueMap<>(userAttributes);
                userAttributes.add(EMAIL_ATTRIBUTE_NAME, user.getEmail());
            }
            addNew = false;
            if (user.getUsername().equals(user.getEmail()) && !user.getUsername().equals(samlPrincipal.getName())) {
                user = user.modifyUsername(samlPrincipal.getName());
            }
            publish(new InvitedUserAuthenticatedEvent(user));
            user = userDatabase.retrieveUserById(invitedUserId);
        }

        boolean userModified = false;
        UaaUser userWithSamlAttributes = getUser(samlPrincipal, userAttributes);
        try {
            if (user == null) {
                user = userDatabase.retrieveUserByName(samlPrincipal.getName(), samlPrincipal.getOrigin());
            }
        } catch (UsernameNotFoundException e) {
            UaaUserPrototype uaaUser = userDatabase.retrieveUserPrototypeByEmail(userWithSamlAttributes.getEmail(), samlPrincipal.getOrigin());
            if (uaaUser != null) {
                userModified = true;
                user = new UaaUser(uaaUser.withUsername(samlPrincipal.getName()));
            } else {
                if (!addNew) {
                    throw new SamlLoginException("SAML user does not exist. "
                            + "You can correct this by creating a shadow user for the SAML user.", e);
                }
                publish(new NewUserAuthenticatedEvent(userWithSamlAttributes));
                try {
                    user = new UaaUser(userDatabase.retrieveUserPrototypeByName(samlPrincipal.getName(), samlPrincipal.getOrigin()));
                } catch (UsernameNotFoundException ex) {
                    throw new BadCredentialsException("Unable to establish shadow user for SAML user:" + samlPrincipal.getName());
                }
            }
        }
        if (haveUserAttributesChanged(user, userWithSamlAttributes)) {
            userModified = true;
            user = user.modifyAttributes(userWithSamlAttributes.getEmail(),
                    userWithSamlAttributes.getGivenName(),
                    userWithSamlAttributes.getFamilyName(),
                    userWithSamlAttributes.getPhoneNumber(),
                    userWithSamlAttributes.getExternalId(),
                    user.isVerified() || userWithSamlAttributes.isVerified());
        }
        publish(
                new ExternalGroupAuthorizationEvent(
                        user,
                        userModified,
                        authorities,
                        true
                )
        );
        user = userDatabase.retrieveUserById(user.getId());
        return user;
    }

    protected UaaUser getUser(UaaPrincipal principal, MultiValueMap<String, String> userAttributes) {
        if (principal.getName() == null && userAttributes.getFirst(EMAIL_ATTRIBUTE_NAME) == null) {
            throw new BadCredentialsException("Cannot determine username from credentials supplied");
        }

        String name = principal.getName();
        return UaaUser.createWithDefaults(u ->
                u.withId(OriginKeys.NotANumber)
                        .withUsername(name)
                        .withEmail(userAttributes.getFirst(EMAIL_ATTRIBUTE_NAME))
                        .withPhoneNumber(userAttributes.getFirst(PHONE_NUMBER_ATTRIBUTE_NAME))
                        .withPassword("")
                        .withGivenName(userAttributes.getFirst(GIVEN_NAME_ATTRIBUTE_NAME))
                        .withFamilyName(userAttributes.getFirst(FAMILY_NAME_ATTRIBUTE_NAME))
                        .withAuthorities(Collections.emptyList())
                        .withVerified(Boolean.valueOf(userAttributes.getFirst(EMAIL_VERIFIED_ATTRIBUTE_NAME)))
                        .withOrigin(principal.getOrigin() != null ? principal.getOrigin() : OriginKeys.LOGIN_SERVER)
                        .withExternalId(name)
                        .withZoneId(principal.getZoneId())
        );
    }

    protected boolean haveUserAttributesChanged(UaaUser existingUser, UaaUser user) {
        return existingUser.isVerified() != user.isVerified() ||
                !StringUtils.equals(existingUser.getGivenName(), user.getGivenName()) ||
                !StringUtils.equals(existingUser.getFamilyName(), user.getFamilyName()) ||
                !StringUtils.equals(existingUser.getPhoneNumber(), user.getPhoneNumber()) ||
                !StringUtils.equals(existingUser.getEmail(), user.getEmail()) ||
                !StringUtils.equals(existingUser.getExternalId(), user.getExternalId());
    }

    /* ****************************************************
    ApplicationEventPublisherAware
    **************************************************** */

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.eventPublisher = applicationEventPublisher;
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }
}
