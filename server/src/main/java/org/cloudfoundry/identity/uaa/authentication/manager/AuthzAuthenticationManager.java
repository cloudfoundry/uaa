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
package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.authentication.MfaAuthenticationRequiredException;
import org.cloudfoundry.identity.uaa.authentication.PasswordChangeRequiredException;
import org.cloudfoundry.identity.uaa.authentication.PasswordExpiredException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UnverifiedUserAuthenticationEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.logging.SanitizedLogFactory;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Locale;

/**
 * @author Luke Taylor
 * @author Dave Syer
 *
 */
public class AuthzAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware {

    private final SanitizedLogFactory.SanitizedLog logger = SanitizedLogFactory.getLog(getClass());
    private final PasswordEncoder encoder;
    private final UaaUserDatabase userDatabase;
    private ApplicationEventPublisher eventPublisher;
    private AccountLoginPolicy accountLoginPolicy = new PermitAllAccountLoginPolicy();
    private IdentityProviderProvisioning providerProvisioning;

    private String origin;
    private boolean allowUnverifiedUsers = true;

    public AuthzAuthenticationManager(UaaUserDatabase cfusers, IdentityProviderProvisioning providerProvisioning) {
        this(cfusers, new BCryptPasswordEncoder(), providerProvisioning);
    }

    public AuthzAuthenticationManager(UaaUserDatabase userDatabase, PasswordEncoder encoder, IdentityProviderProvisioning providerProvisioning) {
        this.userDatabase = userDatabase;
        this.encoder = encoder;
        this.providerProvisioning = providerProvisioning;
    }

    @Override
    public Authentication authenticate(Authentication req) throws AuthenticationException {
        logger.debug("Processing authentication request for " + req.getName());

        if (req.getCredentials() == null) {
            BadCredentialsException e = new BadCredentialsException("No password supplied");
            publish(new AuthenticationFailureBadCredentialsEvent(req, e));
            throw e;
        }

        UaaUser user = getUaaUser(req);

        if (user == null) {
            logger.debug("No user named '" + req.getName() + "' was found for origin:"+ origin);
            publish(new UserNotFoundEvent(req));
        } else {
            if (!accountLoginPolicy.isAllowed(user, req)) {
                logger.warn("Login policy rejected authentication for " + user.getUsername() + ", " + user.getId()
                        + ". Ignoring login request.");
                AuthenticationPolicyRejectionException e = new AuthenticationPolicyRejectionException("Your account has been locked because of too many failed attempts to login.");
                publish(new AuthenticationFailureLockedEvent(req, e));
                throw e;
            }

            boolean passwordMatches = ((CharSequence) req.getCredentials()).length() != 0 && encoder.matches((CharSequence) req.getCredentials(), user.getPassword());

            if (!passwordMatches) {
                logger.debug("Password did not match for user " + req.getName());
                publish(new UserAuthenticationFailureEvent(user, req));
            } else {
                logger.debug("Password successfully matched for userId["+user.getUsername()+"]:"+user.getId());

                if (!(allowUnverifiedUsers && user.isLegacyVerificationBehavior()) && !user.isVerified()) {
                    publish(new UnverifiedUserAuthenticationEvent(user, req));
                    logger.debug("Account not verified: " + user.getId());
                    throw new AccountNotVerifiedException("Account not verified");
                }


                checkPasswordExpired(user.getPasswordLastModified());

                UaaAuthentication success = new UaaAuthentication(
                        new UaaPrincipal(user),
                        user.getAuthorities(),
                        (UaaAuthenticationDetails) req.getDetails());

                success.setAuthenticationMethods(Collections.singleton("pwd"));
                Date passwordNewerThan = getPasswordNewerThan();
                if(passwordNewerThan != null) {
                    if(user.getPasswordLastModified() == null || (passwordNewerThan.getTime() > user.getPasswordLastModified().getTime())) {
                        logger.info("Password change required for user: "+user.getEmail());
                        throw new PasswordChangeRequiredException(success, "User password needs to be changed");
                    }
                }
                
                if(user.isPasswordChangeRequired()){
                    logger.info("Password change required for user: "+user.getEmail());
                    throw new PasswordChangeRequiredException(success, "User password needs to be changed");
                }

                if(IdentityZoneHolder.get().getConfig().getMfaConfig().isEnabled()) {
                    throw new MfaAuthenticationRequiredException(success, "Mfa authentication required");
                }

                publish(new UserAuthenticationSuccessEvent(user, success));

                return success;
            }
        }

        BadCredentialsException e = new BadCredentialsException("Bad credentials");
        publish(new AuthenticationFailureBadCredentialsEvent(req, e));
        throw e;
    }

    protected int getPasswordExpiresInMonths() {
        int result = 0;
        IdentityProvider provider = providerProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        if (provider!=null) {
            UaaIdentityProviderDefinition idpDefinition = ObjectUtils.castInstance(provider.getConfig(),UaaIdentityProviderDefinition.class);
            if (idpDefinition!=null) {
                if (null!=idpDefinition.getPasswordPolicy()) {
                    return idpDefinition.getPasswordPolicy().getExpirePasswordInMonths();
                }
            }
        }
        return result;
    }

    protected Date getPasswordNewerThan() {
        Date result = null;
        IdentityProvider provider = providerProvisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        if(provider != null) {
            UaaIdentityProviderDefinition idpDefinition = ObjectUtils.castInstance(provider.getConfig(),UaaIdentityProviderDefinition.class);
            if(idpDefinition != null && idpDefinition.getPasswordPolicy() != null) {
                return idpDefinition.getPasswordPolicy().getPasswordNewerThan();
            }
        }
        return result;
    }

    private UaaUser getUaaUser(Authentication req) {
        try {
            UaaUser user = userDatabase.retrieveUserByName(req.getName().toLowerCase(Locale.US), getOrigin());
            if (user!=null) {
                return user;
            }
        } catch (UsernameNotFoundException e) {
        }
        return null;
    }

    private void publish(ApplicationEvent event) {
        if (eventPublisher != null) {
            eventPublisher.publishEvent(event);
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }

    public AccountLoginPolicy getAccountLoginPolicy() {
        return this.accountLoginPolicy;
    }

    public void setAccountLoginPolicy(AccountLoginPolicy accountLoginPolicy) {
        this.accountLoginPolicy = accountLoginPolicy;
    }

    public String getOrigin() {
        return origin;
    }

    public void setOrigin(String origin) {
        this.origin = origin;
    }

    public void setAllowUnverifiedUsers(boolean allowUnverifiedUsers) {
        this.allowUnverifiedUsers = allowUnverifiedUsers;
    }

    private void checkPasswordExpired(Date passwordLastModified) {
        int expiringPassword = getPasswordExpiresInMonths();
        if (expiringPassword>0) {
            Calendar cal = Calendar.getInstance();
            cal.setTimeInMillis(passwordLastModified.getTime());
            cal.add(Calendar.MONTH, expiringPassword);
            if (cal.getTimeInMillis() < System.currentTimeMillis()) {
                throw new PasswordExpiredException("Your current password has expired. Please reset your password.");
            }
        }
    }
}
