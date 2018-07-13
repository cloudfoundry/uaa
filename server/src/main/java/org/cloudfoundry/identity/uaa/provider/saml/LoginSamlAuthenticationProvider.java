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
package org.cloudfoundry.identity.uaa.provider.saml;


import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.ExternalGroupAuthorizationEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.InvitedUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.NewUserAuthenticatedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMember;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.user.UserInfo;
import org.cloudfoundry.identity.uaa.util.UaaUrlUtils;
import org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSBase64Binary;
import org.opensaml.core.xml.schema.XSBoolean;
import org.opensaml.core.xml.schema.XSBooleanValue;
import org.opensaml.core.xml.schema.XSDateTime;
import org.opensaml.core.xml.schema.XSInteger;
import org.opensaml.core.xml.schema.XSQName;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.XSURI;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.saml.SamlAuthentication;
import org.springframework.security.saml.provider.provisioning.SamlProviderProvisioning;
import org.springframework.security.saml.provider.service.ServiceProviderService;
import org.springframework.security.saml.saml2.authentication.Assertion;
import org.springframework.security.saml.saml2.authentication.AuthenticationContextClassReference;
import org.springframework.security.saml.saml2.authentication.AuthenticationStatement;
import org.springframework.security.saml.saml2.metadata.IdentityProviderMetadata;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import static java.util.Optional.of;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_VERIFIED_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken.AUTHENTICATION_CONTEXT_CLASS_REFERENCE;
import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.isAcceptedInvitationAuthentication;
import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.retainAllMatches;

public class LoginSamlAuthenticationProvider implements AuthenticationManager,ApplicationEventPublisherAware {
    private final static Log logger = LogFactory.getLog(LoginSamlAuthenticationProvider.class);
    private UaaUserDatabase userDatabase;
    private ApplicationEventPublisher eventPublisher;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private ScimGroupExternalMembershipManager externalMembershipManager;
    private SamlProviderProvisioning<ServiceProviderService> resolver;

    public void setIdentityProviderProvisioning(IdentityProviderProvisioning identityProviderProvisioning) {
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    public void setUserDatabase(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    public void setExternalMembershipManager(ScimGroupExternalMembershipManager externalMembershipManager) {
        this.externalMembershipManager = externalMembershipManager;
    }

    public LoginSamlAuthenticationProvider setResolver(SamlProviderProvisioning<ServiceProviderService> resolver) {
        this.resolver = resolver;
        return this;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!(authentication instanceof SamlAuthentication)) {
            throw new IllegalArgumentException("Only SAMLAuthenticationToken is supported, " + authentication.getClass() + " was attempted");
        }

        IdentityZone zone = IdentityZoneHolder.get();
        logger.debug(String.format("Initiating SAML authentication in zone '%s' domain '%s'", zone.getId(), zone.getSubdomain()));
        SamlAuthentication token = (SamlAuthentication) authentication;
        IdentityProviderMetadata idpm = resolver.getHostedProvider().getRemoteProvider(token.getAssertingEntityId());
        String alias = idpm.getEntityAlias();
        String relayState = token.getRelayState();
        boolean addNew;
        IdentityProvider<SamlIdentityProviderDefinition> idp;
        SamlIdentityProviderDefinition samlConfig;
        try {
            idp = identityProviderProvisioning.retrieveByOrigin(alias, IdentityZoneHolder.get().getId());
            samlConfig = idp.getConfig();
            addNew = samlConfig.isAddShadowUserOnLogin();
            if (!idp.isActive()) {
                throw new ProviderNotFoundException("Identity Provider has been disabled by administrator for alias:"+alias);
            }
        } catch (EmptyResultDataAccessException x) {
            throw new ProviderNotFoundException("No SAML identity provider found in zone for alias:"+alias);
        }

        String username = token.getSamlPrincipal().getValue();
        UaaPrincipal samlPrincipal = new UaaPrincipal(OriginKeys.NotANumber, username, username, alias, username, zone.getId());
        logger.debug(
            String.format(
                "Mapped SAML authentication to IDP with origin '%s' and username '%s'",
                idp.getOriginKey(),
                samlPrincipal.getName()
            )
        );

        Collection<? extends GrantedAuthority> samlAuthorities = retrieveSamlAuthorities(samlConfig, token);

        Collection<? extends GrantedAuthority> authorities = null;
        SamlIdentityProviderDefinition.ExternalGroupMappingMode groupMappingMode = idp.getConfig().getGroupMappingMode();
        switch (groupMappingMode) {
            case EXPLICITLY_MAPPED:
                authorities = mapAuthorities(idp.getOriginKey(), samlAuthorities);
            break;
            case AS_SCOPES:
                authorities = new LinkedList<>(samlAuthorities);
            break;
        }

        Set<String> filteredExternalGroups = filterSamlAuthorities(samlConfig, samlAuthorities);
        MultiValueMap<String, String> userAttributes = retrieveUserAttributes(samlConfig, token);

        if (samlConfig.getAuthnContext() != null) {
            if (Collections.disjoint(userAttributes.get(AUTHENTICATION_CONTEXT_CLASS_REFERENCE), samlConfig.getAuthnContext())) {
                throw new BadCredentialsException("Identity Provider did not authenticate with the requested AuthnContext.");
            }
        }
        long sessionExpiration = getAuthenticationExpiration(token.getAssertion());
        UaaUser user = createIfMissing(samlPrincipal, addNew, authorities, userAttributes);
        UaaPrincipal principal = new UaaPrincipal(user);
        UaaAuthentication resultUaaAuthentication = new LoginSamlAuthenticationToken(principal, token)
            .getUaaAuthentication(user.getAuthorities(),
                                  filteredExternalGroups,
                                  userAttributes,
                                  sessionExpiration
            );
        publish(new IdentityProviderAuthenticationSuccessEvent(user, resultUaaAuthentication, OriginKeys.SAML));
        if (samlConfig.isStoreCustomAttributes()) {
            userDatabase.storeUserInfo(user.getId(),
                                       new UserInfo()
                                           .setUserAttributes(resultUaaAuthentication.getUserAttributes())
                                           .setRoles(new LinkedList(resultUaaAuthentication.getExternalGroups()))
            );
        }
        configureRelayRedirect(relayState);

        return resultUaaAuthentication;
    }

    protected long getAuthenticationExpiration(Assertion assertion) {
        long result = Long.MAX_VALUE;
        for (AuthenticationStatement statement : assertion.getAuthenticationStatements()) {
            DateTime sessionNotOnOrAfter = statement.getSessionNotOnOrAfter();
            if (sessionNotOnOrAfter!=null) {
                result = Math.min(result, sessionNotOnOrAfter.getMillis());
            }
        }
        return result;
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

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    protected Set<String> filterSamlAuthorities(SamlIdentityProviderDefinition definition, Collection<? extends GrantedAuthority> samlAuthorities) {
        List<String> whiteList = of(definition.getExternalGroupsWhitelist()).orElse(Collections.EMPTY_LIST);
        Set<String> authorities = samlAuthorities.stream().map(s -> s.getAuthority()).collect(Collectors.toSet());
        Set<String> result = retainAllMatches(authorities, whiteList);
        logger.debug(String.format("White listed external SAML groups:'%s'", result));
        return result;
    }

    protected Collection<? extends GrantedAuthority> mapAuthorities(String origin, Collection<? extends GrantedAuthority> authorities) {
        Collection<GrantedAuthority> result = new LinkedList<>();
        logger.debug("Mapping SAML authorities:" + authorities);
        for (GrantedAuthority authority : authorities ) {
            String externalGroup = authority.getAuthority();
            logger.debug("Attempting to map external group: "+externalGroup);
            for (ScimGroupExternalMember internalGroup : externalMembershipManager.getExternalGroupMapsByExternalGroup(externalGroup, origin, IdentityZoneHolder.get().getId())) {
                String internalName = internalGroup.getDisplayName();
                logger.debug(String.format("Mapped external: '%s' to internal: '%s'", externalGroup, internalName));
                result.add(new SimpleGrantedAuthority(internalName));
            }
        }
        return result;
    }

    public Collection<? extends GrantedAuthority> retrieveSamlAuthorities(SamlIdentityProviderDefinition definition, SamlAuthentication credential)  {
        Collection<SamlUserAuthority> authorities = new ArrayList<>();
        if (definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME)!=null) {
            List<String> attributeNames = new LinkedList<>();
            if (definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME) instanceof String) {
                attributeNames.add((String) definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME));
            } else if (definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME) instanceof Collection) {
                attributeNames.addAll((Collection) definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME));
            }
            for (org.springframework.security.saml.saml2.attribute.Attribute attribute : credential.getAssertion().getAttributes()) {
                if ((attributeNames.contains(attribute.getName())) || (attributeNames.contains(attribute.getFriendlyName()))) {
                    if (attribute.getValues() != null && attribute.getValues().size() > 0) {
                        for (Object group : attribute.getValues()) {
                            authorities.add(new SamlUserAuthority(getStringValue(attribute.getName(),definition,group)));
                        }
                    }
                }
            }
        }
        return authorities == null ? Collections.EMPTY_LIST : authorities;
    }

    public MultiValueMap<String, String> retrieveUserAttributes(SamlIdentityProviderDefinition definition, SamlAuthentication credential) {
        logger.debug(String.format("Retrieving SAML user attributes [zone:%s, origin:%s]", definition.getZoneId(), definition.getIdpEntityAlias()));
        MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
        if (definition != null && definition.getAttributeMappings() != null) {
            for (Entry<String, Object> attributeMapping : definition.getAttributeMappings().entrySet()) {
                if (attributeMapping.getValue() instanceof  String) {
                    if (credential.getAssertion().getFirstAttribute((String)attributeMapping.getValue()) != null) {
                        String key = attributeMapping.getKey();
                        for (Object xmlObject : credential.getAssertion().getFirstAttribute((String) attributeMapping.getValue()).getValues()) {
                            String value = getStringValue(key, definition, xmlObject);
                            if (value!=null) {
                                userAttributes.add(key, value);
                            }
                        }
                    }
                }
            }
        }
        if (credential.getAssertion().getAuthenticationStatements() != null) {

            for (AuthenticationStatement statement : credential.getAssertion().getAuthenticationStatements()) {
                if (statement.getAuthenticationContext() != null &&
                    statement.getAuthenticationContext().getClassReference() != null) {
                    AuthenticationContextClassReference ref = statement.getAuthenticationContext().getClassReference();
                    userAttributes.add(AUTHENTICATION_CONTEXT_CLASS_REFERENCE, ref.toString());
                }
            }
        }
        return userAttributes;
    }

    protected String getStringValue(String key, SamlIdentityProviderDefinition definition, Object xmlObject) {
        String value = null;
        if (xmlObject instanceof XSString) {
            value = ((XSString) xmlObject).getValue();
        } else if (xmlObject instanceof XSAny) {
            value = ((XSAny)xmlObject).getTextContent();
        } else if (xmlObject instanceof XSInteger) {
            Integer i =  ((XSInteger)xmlObject).getValue();
            value = i!=null ? i.toString() : null;
        } else if (xmlObject instanceof XSBoolean) {
            XSBooleanValue b =  ((XSBoolean)xmlObject).getValue();
            value = b!=null && b.getValue()!=null ? b.getValue().toString() : null;
        } else if (xmlObject instanceof XSDateTime) {
            DateTime d =  ((XSDateTime)xmlObject).getValue();
            value = d!=null ? d.toString() : null;
        } else if (xmlObject instanceof XSQName) {
            QName name = ((XSQName) xmlObject).getValue();
            value = name!=null ? name.toString() : null;
        } else if (xmlObject instanceof XSURI) {
            value = ((XSURI) xmlObject).getValue();
        } else if (xmlObject instanceof XSBase64Binary) {
            value = ((XSBase64Binary) xmlObject).getValue();
        } else if (xmlObject != null) {
            value = xmlObject.toString();
        }

        if (value!=null) {
            logger.debug(String.format("Found SAML user attribute %s of value %s [zone:%s, origin:%s]", key, value, definition.getZoneId(), definition.getIdpEntityAlias()));
            return value;
        }  else if (xmlObject !=null){
            logger.debug(String.format("SAML user attribute %s at is not of type XSString or other recognizable type, %s [zone:%s, origin:%s]", key, xmlObject.getClass().getName(),definition.getZoneId(), definition.getIdpEntityAlias()));
        }
        return null;
    }

    protected UaaUser createIfMissing(UaaPrincipal samlPrincipal, boolean addNew, Collection<? extends GrantedAuthority> authorities, MultiValueMap<String, String> userAttributes) {
        UaaUser user = null;
        String invitedUserId = null;
        boolean is_invitation_acceptance = isAcceptedInvitationAuthentication();
        if (is_invitation_acceptance) {
            invitedUserId = (String) RequestContextHolder.currentRequestAttributes().getAttribute("user_id", RequestAttributes.SCOPE_SESSION);
            user = userDatabase.retrieveUserById(invitedUserId);
            if ( userAttributes.getFirst(EMAIL_ATTRIBUTE_NAME) != null ) {
                if (!userAttributes.getFirst(EMAIL_ATTRIBUTE_NAME).equalsIgnoreCase(user.getEmail()) ) {
                    throw new BadCredentialsException("SAML User email mismatch. Authenticated email doesn't match invited email.");
                }
            } else {
                userAttributes = new LinkedMultiValueMap<>(userAttributes);
                userAttributes.add(EMAIL_ATTRIBUTE_NAME, user.getEmail());
            }
            addNew = false;
            if(user.getUsername().equals(user.getEmail()) && !user.getUsername().equals(samlPrincipal.getName())) {
                user = user.modifyUsername(samlPrincipal.getName());
            }
            publish(new InvitedUserAuthenticatedEvent(user));
            user = userDatabase.retrieveUserById(invitedUserId);
        }

        boolean userModified = false;
        UaaUser userWithSamlAttributes = getUser(samlPrincipal, userAttributes);
        try {
            if (user==null) {
                user = userDatabase.retrieveUserByName(samlPrincipal.getName(), samlPrincipal.getOrigin());
            }
        } catch (UsernameNotFoundException e) {
            UaaUser uaaUser = userDatabase.retrieveUserByEmail(userWithSamlAttributes.getEmail(), samlPrincipal.getOrigin());
            if (uaaUser != null) {
                userModified = true;
                user = uaaUser.modifyUsername(samlPrincipal.getName());
            } else {
                if (!addNew) {
                    throw new LoginSAMLException("SAML user does not exist. "
                            + "You can correct this by creating a shadow user for the SAML user.", e);
                }
                publish(new NewUserAuthenticatedEvent(userWithSamlAttributes));
                try {
                    user = userDatabase.retrieveUserByName(samlPrincipal.getName(), samlPrincipal.getOrigin());
                } catch (UsernameNotFoundException ex) {
                    throw new BadCredentialsException("Unable to establish shadow user for SAML user:"+ samlPrincipal.getName());
                }
            }
        }
        if (haveUserAttributesChanged(user, userWithSamlAttributes)) {
            userModified = true;
            user = user.modifyAttributes(userWithSamlAttributes.getEmail(),
                                         userWithSamlAttributes.getGivenName(),
                                         userWithSamlAttributes.getFamilyName(),
                                         userWithSamlAttributes.getPhoneNumber(),
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

    protected UaaUser getUser(UaaPrincipal principal, MultiValueMap<String,String> userAttributes) {
        String name = principal.getName();
        String email = userAttributes.getFirst(EMAIL_ATTRIBUTE_NAME);
        String givenName = userAttributes.getFirst(GIVEN_NAME_ATTRIBUTE_NAME);
        String familyName = userAttributes.getFirst(FAMILY_NAME_ATTRIBUTE_NAME);
        String phoneNumber = userAttributes.getFirst(PHONE_NUMBER_ATTRIBUTE_NAME);
        String emailVerified = userAttributes.getFirst(EMAIL_VERIFIED_ATTRIBUTE_NAME);
        String userId = OriginKeys.NotANumber;
        String origin = principal.getOrigin()!=null?principal.getOrigin(): OriginKeys.LOGIN_SERVER;
        String zoneId = principal.getZoneId();
        if (name == null && email != null) {
            name = email;
        }
        if (name == null && OriginKeys.NotANumber.equals(userId)) {
            throw new BadCredentialsException("Cannot determine username from credentials supplied");
        } else if (name==null) {
            //we have user_id, name is irrelevant
            name="unknown";
        }
        if (email == null) {
            if (name.contains("@")) {
                if (name.split("@").length == 2 && !name.startsWith("@") && !name.endsWith("@")) {
                    email = name;
                } else {
                    email = name.replaceAll("@", "") + "@unknown.org";
                }
            }
            else {
                email = name + "@unknown.org";
            }
        }
        if (givenName == null) {
            givenName = email.split("@")[0];
        }
        if (familyName == null) {
            familyName = email.split("@")[1];
        }
        return new UaaUser(
        new UaaUserPrototype()
            .withVerified(Boolean.valueOf(emailVerified))
            .withEmail(email)
            .withGivenName(givenName)
            .withFamilyName(familyName)
            .withPhoneNumber(phoneNumber)
            .withModified(new Date())
            .withId(userId)
            .withUsername(name)
            .withPassword("")
            .withAuthorities(Collections.EMPTY_LIST)
            .withCreated(new Date())
            .withOrigin(origin)
            .withExternalId(name)
            .withZoneId(zoneId)
            .withSalt(null)
            .withPasswordLastModified(null));
    }

    protected boolean haveUserAttributesChanged(UaaUser existingUser, UaaUser user) {
        if (existingUser.isVerified() != user.isVerified() ||
            !StringUtils.equals(existingUser.getGivenName(), user.getGivenName()) ||
            !StringUtils.equals(existingUser.getFamilyName(), user.getFamilyName()) ||
            !StringUtils.equals(existingUser.getPhoneNumber(), user.getPhoneNumber()) ||
            !StringUtils.equals(existingUser.getEmail(), user.getEmail())) {
            return true;
        }
        return false;
    }
}
