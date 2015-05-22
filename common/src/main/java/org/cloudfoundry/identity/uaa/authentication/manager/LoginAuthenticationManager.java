/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication.manager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

import java.util.Date;
import java.util.Map;

public class LoginAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware {
    public static final String NotANumber = Origin.NotANumber;

    private final Log logger = LogFactory.getLog(getClass());

    private ApplicationEventPublisher eventPublisher;

    private UaaUserDatabase userDatabase;

    private RandomValueStringGenerator generator = new RandomValueStringGenerator();

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

    @Override
    public Authentication authenticate(Authentication request) throws AuthenticationException {

        if (!(request instanceof AuthzAuthenticationRequest)) {
            logger.debug("Cannot process request of type: " + request.getClass().getName());
            return null;
        }

        AuthzAuthenticationRequest req = (AuthzAuthenticationRequest) request;
        Map<String, String> info = req.getInfo();
        logger.debug("Processing authentication request for " + req.getName());

        SecurityContext context = SecurityContextHolder.getContext();

        if (context.getAuthentication() instanceof OAuth2Authentication) {
            OAuth2Authentication authentication = (OAuth2Authentication) context.getAuthentication();
            if (authentication.isClientOnly()) {
                UaaUser user = getUser(req, info);
                UaaAuthenticationDetails authdetails = (UaaAuthenticationDetails) req.getDetails();
                boolean addNewAccounts = authdetails != null
                                &&
                                authdetails.getExtendedAuthorizationInfo() != null
                                &&
                                Boolean.parseBoolean(authdetails.getExtendedAuthorizationInfo().get(
                                                UaaAuthenticationDetails.ADD_NEW));
                try {
                    if (NotANumber.equals(user.getId())) {
                        user = userDatabase.retrieveUserByName(user.getUsername(), user.getOrigin());
                    } else {
                        //we should never add new accounts if we specify user_id
                        addNewAccounts = false;
                        user = userDatabase.retrieveUserById(user.getId());
                    }
                } catch (UsernameNotFoundException e) {
                    // Not necessarily fatal
                    if (addNewAccounts) {
                        // Register new users automatically
                        publish(new NewUserAuthenticatedEvent(user));
                        try {
                            user = userDatabase.retrieveUserByName(user.getUsername(), user.getOrigin());
                        } catch (UsernameNotFoundException ex) {
                            throw new BadCredentialsException("Bad credentials");
                        }
                    } else  {
                        //if add_new=false then this is a bad user ID
                        throw new BadCredentialsException("Bad Credentials");
                    }
                }
                Authentication success = new UaaAuthentication(new UaaPrincipal(user), user.getAuthorities(),
                                authdetails);
                publish(new UserAuthenticationSuccessEvent(user, success));
                return success;
            }
        }

        logger.debug("Did not locate login credentials");
        return null;
    }

    protected void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    protected UaaUser getUser(AuthzAuthenticationRequest req, Map<String, String> info) {
        String name = req.getName();
        String email = info.get("email");
        String userId = info.get("user_id")!=null?info.get("user_id"):NotANumber;
        String origin = info.get(Origin.ORIGIN)!=null?info.get(Origin.ORIGIN):Origin.LOGIN_SERVER;

        if (name == null && email != null) {
            name = email;
        }
        if (name == null && NotANumber.equals(userId)) {
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
        String givenName = info.get("given_name");
        if (givenName == null) {
            givenName = email.split("@")[0];
        }
        String familyName = info.get("family_name");
        if (familyName == null) {
            familyName = email.split("@")[1];
        }
        return new UaaUser(
            userId,
            name,
            "" /*zero length password for login server */,
            email,
            UaaAuthority.USER_AUTHORITIES,
            givenName,
            familyName,
            new Date(),
            new Date(),
            origin,
            name,
            false,
            IdentityZoneHolder.get().getId(),
            null);

    }
}
