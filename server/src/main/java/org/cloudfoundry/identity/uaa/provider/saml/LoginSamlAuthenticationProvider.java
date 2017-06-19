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


import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
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
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSBase64Binary;
import org.opensaml.xml.schema.XSBoolean;
import org.opensaml.xml.schema.XSBooleanValue;
import org.opensaml.xml.schema.XSDateTime;
import org.opensaml.xml.schema.XSInteger;
import org.opensaml.xml.schema.XSQName;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.XSURI;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.SAMLCredential;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.userdetails.SAMLUserDetailsService;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EMAIL_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.FAMILY_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GIVEN_NAME_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.GROUP_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.PHONE_NUMBER_ATTRIBUTE_NAME;
import static org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken.AUTHENTICATION_CONTEXT_CLASS_REFERENCE;
import static org.cloudfoundry.identity.uaa.util.UaaHttpRequestUtils.isAcceptedInvitationAuthentication;

public class LoginSamlAuthenticationProvider extends SAMLAuthenticationProvider implements ApplicationEventPublisherAware {
    private final static Log logger = LogFactory.getLog(LoginSamlAuthenticationProvider.class);
    private UaaUserDatabase userDatabase;
    private ApplicationEventPublisher eventPublisher;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private ScimGroupExternalMembershipManager externalMembershipManager;

    public void setIdentityProviderProvisioning(IdentityProviderProvisioning identityProviderProvisioning) {
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    public void setUserDatabase(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    public void setExternalMembershipManager(ScimGroupExternalMembershipManager externalMembershipManager) {
        this.externalMembershipManager = externalMembershipManager;
    }

    @Override
    public void setUserDetails(SAMLUserDetailsService userDetails) {
        super.setUserDetails(userDetails);
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            throw new IllegalArgumentException("Only SAMLAuthenticationToken is supported, " + authentication.getClass() + " was attempted");
        }

        IdentityZone zone = IdentityZoneHolder.get();

        SAMLAuthenticationToken token = (SAMLAuthenticationToken) authentication;
        SAMLMessageContext context = token.getCredentials();
        String alias = context.getPeerExtendedMetadata().getAlias();
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
        ExpiringUsernameAuthenticationToken result = getExpiringUsernameAuthenticationToken(authentication);
        UaaPrincipal samlPrincipal = new UaaPrincipal(OriginKeys.NotANumber, result.getName(), result.getName(), alias, result.getName(), zone.getId());
        Collection<? extends GrantedAuthority> samlAuthorities = retrieveSamlAuthorities(samlConfig, (SAMLCredential) result.getCredentials());

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
        MultiValueMap<String, String> userAttributes = retrieveUserAttributes(samlConfig, (SAMLCredential) result.getCredentials());
        UaaUser user = createIfMissing(samlPrincipal, addNew, authorities, userAttributes);
        UaaPrincipal principal = new UaaPrincipal(user);
        UaaAuthentication resultUaaAuthentication = new LoginSamlAuthenticationToken(principal, result).getUaaAuthentication(user.getAuthorities(), filteredExternalGroups, userAttributes);
        publish(new UserAuthenticationSuccessEvent(user, resultUaaAuthentication));
        if (samlConfig.isStoreCustomAttributes()) {
            userDatabase.storeUserInfo(user.getId(),
                                       new UserInfo()
                                           .setUserAttributes(resultUaaAuthentication.getUserAttributes())
                                           .setRoles(new LinkedList(resultUaaAuthentication.getExternalGroups()))
            );
        }
        return resultUaaAuthentication;
    }

    protected ExpiringUsernameAuthenticationToken getExpiringUsernameAuthenticationToken(Authentication authentication) {
        return (ExpiringUsernameAuthenticationToken)super.authenticate(authentication);
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    protected Set<String> filterSamlAuthorities(SamlIdentityProviderDefinition definition, Collection<? extends GrantedAuthority> samlAuthorities) {
        List<String> whiteList = Optional.of(definition.getExternalGroupsWhitelist()).orElse(Collections.EMPTY_LIST);
        Set<String> authorities = samlAuthorities.stream().map(s -> s.getAuthority()).collect(Collectors.toSet());
        return UaaStringUtils.retainAllMatches(authorities, whiteList);
    }

    protected Collection<? extends GrantedAuthority> mapAuthorities(String origin, Collection<? extends GrantedAuthority> authorities) {
        Collection<GrantedAuthority> result = new LinkedList<>();
            for (GrantedAuthority authority : authorities ) {
                String externalGroup = authority.getAuthority();
                    for (ScimGroupExternalMember internalGroup : externalMembershipManager.getExternalGroupMapsByExternalGroup(externalGroup, origin)) {
                        result.add(new SimpleGrantedAuthority(internalGroup.getDisplayName()));
                    }
            }
        return result;
    }

    public Collection<? extends GrantedAuthority> retrieveSamlAuthorities(SamlIdentityProviderDefinition definition, SAMLCredential credential)  {
        Collection<SamlUserAuthority> authorities = new ArrayList<>();
        if (definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME)!=null) {
            List<String> attributeNames = new LinkedList<>();
            if (definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME) instanceof String) {
                attributeNames.add((String) definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME));
            } else if (definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME) instanceof Collection) {
                attributeNames.addAll((Collection) definition.getAttributeMappings().get(GROUP_ATTRIBUTE_NAME));
            }
            for (Attribute attribute : credential.getAttributes()) {
                if ((attributeNames.contains(attribute.getName())) || (attributeNames.contains(attribute.getFriendlyName()))) {
                    if (attribute.getAttributeValues() != null && attribute.getAttributeValues().size() > 0) {
                        for (XMLObject group : attribute.getAttributeValues()) {
                            authorities.add(new SamlUserAuthority(getStringValue(attribute.getName(),definition,group)));
                        }
                    }
                }
            }
        }
        return authorities == null ? Collections.EMPTY_LIST : authorities;
    }

    public MultiValueMap<String, String> retrieveUserAttributes(SamlIdentityProviderDefinition definition, SAMLCredential credential) {
        logger.debug(String.format("Retrieving SAML user attributes [zone:%s, origin:%s]", definition.getZoneId(), definition.getIdpEntityAlias()));
        MultiValueMap<String, String> userAttributes = new LinkedMultiValueMap<>();
        if (definition != null && definition.getAttributeMappings() != null) {
            for (Entry<String, Object> attributeMapping : definition.getAttributeMappings().entrySet()) {
                if (attributeMapping.getValue() instanceof  String) {
                    if (credential.getAttribute((String)attributeMapping.getValue()) != null) {
                        String key = attributeMapping.getKey();
                        for (XMLObject xmlObject : credential.getAttribute((String) attributeMapping.getValue()).getAttributeValues()) {
                            String value = getStringValue(key, definition, xmlObject);
                            if (value!=null) {
                                userAttributes.add(key, value);
                            }
                        }
                    }
                }
            }
        }
        if (credential.getAuthenticationAssertion() != null && credential.getAuthenticationAssertion().getAuthnStatements() != null) {
            for (AuthnStatement statement : credential.getAuthenticationAssertion().getAuthnStatements()) {
                if (statement.getAuthnContext() != null && statement.getAuthnContext().getAuthnContextClassRef() != null) {
                    userAttributes.add(AUTHENTICATION_CONTEXT_CLASS_REFERENCE, statement.getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
                }
            }
        }
        return userAttributes;
    }

    protected String getStringValue(String key, SamlIdentityProviderDefinition definition, XMLObject xmlObject) {
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
                user.setVerified(true);
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
                user = uaaUser.modifyUsername(samlPrincipal.getName());
            } else {
                if (!addNew) {
                    throw new LoginSAMLException("SAML user does not exist. "
                            + "You can correct this by creating a shadow user for the SAML user.", e);
                }
                // Register new users automatically
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
            user = user.modifyAttributes(userWithSamlAttributes.getEmail(), userWithSamlAttributes.getGivenName(), userWithSamlAttributes.getFamilyName(), userWithSamlAttributes.getPhoneNumber());
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
            .withVerified(true)
            .withZoneId(zoneId)
            .withSalt(null)
            .withPasswordLastModified(null));
    }

    private boolean haveUserAttributesChanged(UaaUser existingUser, UaaUser user) {
        if (!StringUtils.equals(existingUser.getGivenName(), user.getGivenName()) || !StringUtils.equals(existingUser.getFamilyName(), user.getFamilyName()) ||
                !StringUtils.equals(existingUser.getPhoneNumber(), user.getPhoneNumber()) || !StringUtils.equals(existingUser.getEmail(), user.getEmail())) {
            return true;
        }
        return false;
    }
}
