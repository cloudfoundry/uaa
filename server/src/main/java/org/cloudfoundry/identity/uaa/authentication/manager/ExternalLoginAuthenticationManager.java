/*
 * ******************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * ******************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication.manager;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.AccountNotPreCreatedException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.user.DialableByPhone;
import org.cloudfoundry.identity.uaa.user.ExternallyIdentifiable;
import org.cloudfoundry.identity.uaa.user.Mailable;
import org.cloudfoundry.identity.uaa.user.Named;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.BeanNameAware;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Date;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

public class ExternalLoginAuthenticationManager<ExternalAuthenticationDetails> implements AuthenticationManager, ApplicationEventPublisherAware, BeanNameAware {

    protected final Log logger = LogFactory.getLog(getClass());

    private ApplicationEventPublisher eventPublisher;

    private UaaUserDatabase userDatabase;

    private String name;

    private String origin = "unknown";

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    /**
     * @param userDatabase the userDatabase to set
     */
    public void setUserDatabase(UaaUserDatabase userDatabase) {
        this.userDatabase = userDatabase;
    }

    public UaaUserDatabase getUserDatabase() {
        return this.userDatabase;
    }

    @Override
    public Authentication authenticate(Authentication request) throws AuthenticationException {
        ExternalAuthenticationDetails authenticationData = getExternalAuthenticationDetails(request);
        UaaUser userFromRequest = getUser(request, authenticationData);
        if (userFromRequest == null) {
            return null;
        }

        UaaUser userFromDb;

        try {
            userFromDb = userDatabase.retrieveUserByName(userFromRequest.getUsername(), getOrigin());
        } catch (UsernameNotFoundException e) {
            userFromDb = userDatabase.retrieveUserByEmail(userFromRequest.getEmail(), getOrigin());
        }

        // Register new users automatically
        if (userFromDb == null) {
            if (!isAddNewShadowUser()) {
                throw new AccountNotPreCreatedException("The user account must be pre-created. Please contact your system administrator.");
            }
            publish(new NewUserAuthenticatedEvent(userFromRequest));
            try {
                userFromDb = userDatabase.retrieveUserByName(userFromRequest.getUsername(), getOrigin());
            } catch (UsernameNotFoundException ex) {
                throw new BadCredentialsException("Unable to register user in internal UAA store.");
            }
        }

        //user is authenticated and exists in UAA
        UaaUser user = userAuthenticated(request, userFromRequest, userFromDb);

        UaaAuthenticationDetails uaaAuthenticationDetails;
        if (request.getDetails() instanceof UaaAuthenticationDetails) {
            uaaAuthenticationDetails = (UaaAuthenticationDetails) request.getDetails();
        } else {
            uaaAuthenticationDetails = UaaAuthenticationDetails.UNKNOWN;
        }
        UaaAuthentication success = new UaaAuthentication(new UaaPrincipal(user), user.getAuthorities(), uaaAuthenticationDetails);
        populateAuthenticationAttributes(success, request, authenticationData);
        publish(new UserAuthenticationSuccessEvent(user, success));
        return success;
    }

    protected void populateAuthenticationAttributes(UaaAuthentication authentication, Authentication request, ExternalAuthenticationDetails authenticationData) {
        if (request.getPrincipal() instanceof UserDetails) {
            UserDetails userDetails = (UserDetails) request.getPrincipal();
            authentication.setUserAttributes(getUserAttributes(userDetails));
            authentication.setExternalGroups(new HashSet<>(getExternalUserAuthorities(userDetails)));
        }
        Set<String> amr = new HashSet<>();
        amr.add("ext");
        authentication.setAuthenticationMethods(amr);
    }

    protected ExternalAuthenticationDetails getExternalAuthenticationDetails(Authentication authentication) {
        return null;
    }

    protected boolean isAddNewShadowUser() {
        return true;
    }

    protected MultiValueMap<String, String> getUserAttributes(UserDetails request) {
        return new LinkedMultiValueMap<>();
    }

    protected List<String> getExternalUserAuthorities(UserDetails request) {
        return new LinkedList<>();
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    protected UaaUser userAuthenticated(Authentication request, UaaUser userFromRequest, UaaUser userFromDb) {
        return userFromDb;
    }

    protected UaaUser getUser(Authentication request, ExternalAuthenticationDetails authDetails) {
        UserDetails userDetails;
        if (request.getPrincipal() instanceof UserDetails) {
            userDetails = (UserDetails) request.getPrincipal();
        } else if (request instanceof UsernamePasswordAuthenticationToken) {
            String username = request.getPrincipal().toString();
            String password = request.getCredentials() != null ? request.getCredentials().toString() : "";
            userDetails = new User(username, password, true, true, true, true, UaaAuthority.USER_AUTHORITIES);
        } else if (request.getPrincipal() == null) {
            logger.debug(this.getClass().getName() + "[" + name + "] cannot process null principal");
            return null;
        } else {
            logger.debug(this.getClass().getName() + "[" + name + "] cannot process request of type: " + request.getClass().getName());
            return null;
        }

        String name = userDetails.getUsername();
        String email = null;

        if (userDetails instanceof Mailable) {
            email = ((Mailable) userDetails).getEmailAddress();

            if (name == null) {
                name = email;
            }
        }

        if (email == null) {
            email = generateEmailIfNull(name);
        }

        String givenName = null;
        String familyName = null;
        if (userDetails instanceof Named) {
            Named names = (Named) userDetails;
            givenName = names.getGivenName();
            familyName = names.getFamilyName();
        }

        String phoneNumber = (userDetails instanceof DialableByPhone) ? ((DialableByPhone) userDetails).getPhoneNumber() : null;
        String externalId = (userDetails instanceof ExternallyIdentifiable) ? ((ExternallyIdentifiable) userDetails).getExternalId() : name;

        UaaUserPrototype userPrototype = new UaaUserPrototype()
                .withUsername(name)
                .withPassword("")
                .withEmail(email)
                .withAuthorities(UaaAuthority.USER_AUTHORITIES)
                .withGivenName(givenName)
                .withFamilyName(familyName)
                .withCreated(new Date())
                .withModified(new Date())
                .withOrigin(origin)
                .withExternalId(externalId)
                .withZoneId(IdentityZoneHolder.get().getId())
                .withPhoneNumber(phoneNumber);

        return new UaaUser(userPrototype);
    }

    protected String generateEmailIfNull(String name) {
        String email;
        if (name != null) {
            if (name.contains("@")) {
                if (name.split("@").length == 2 && !name.startsWith("@") && !name.endsWith("@")) {
                    email = name;
                } else {
                    email = name.replaceAll("@", "") + "@user.from." + getOrigin() + ".cf";
                }
            } else {
                email = name + "@user.from." + getOrigin() + ".cf";
            }
        } else {
            throw new BadCredentialsException("Cannot determine username from credentials supplied");
        }
        return email;
    }

    protected boolean haveUserAttributesChanged(UaaUser existingUser, UaaUser user) {
        if (!StringUtils.equals(existingUser.getGivenName(), user.getGivenName()) || !StringUtils.equals(existingUser.getFamilyName(), user.getFamilyName()) ||
            !StringUtils.equals(existingUser.getPhoneNumber(), user.getPhoneNumber()) || !StringUtils.equals(existingUser.getEmail(), user.getEmail())) {
            return true;
        }
        return false;
    }

    @Override
    public void setBeanName(String name) {
        this.name = name;
    }

}
