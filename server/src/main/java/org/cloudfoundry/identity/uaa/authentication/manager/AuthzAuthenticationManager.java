package org.cloudfoundry.identity.uaa.authentication.manager;

import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UnverifiedUserAuthenticationEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.logging.SanitizedLogFactory;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.ObjectUtils;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.beans.factory.annotation.Qualifier;
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
import org.springframework.security.crypto.password.PasswordEncoder;

import jakarta.servlet.http.HttpSession;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.Locale;

public class AuthzAuthenticationManager implements AuthenticationManager, ApplicationEventPublisherAware {
    private final HttpSession httpSession;
    private final SanitizedLogFactory.SanitizedLog logger = SanitizedLogFactory.getLog(getClass());
    private final PasswordEncoder encoder;
    private final UaaUserDatabase userDatabase;
    private ApplicationEventPublisher eventPublisher;
    private AccountLoginPolicy accountLoginPolicy;
    private final IdentityProviderProvisioning providerProvisioning;

    private String origin;
    private boolean allowUnverifiedUsers = true;

    public AuthzAuthenticationManager(UaaUserDatabase userDatabase,
            @Qualifier("nonCachingPasswordEncoder") PasswordEncoder encoder,
            @Qualifier("identityProviderProvisioning") IdentityProviderProvisioning providerProvisioning,
            HttpSession httpSession) {
        this.userDatabase = userDatabase;
        this.encoder = encoder;
        this.providerProvisioning = providerProvisioning;
        this.httpSession = httpSession;
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
            logger.debug("No user named '" + req.getName() + "' was found for origin:" + origin);
            publish(new UserNotFoundEvent(req, IdentityZoneHolder.getCurrentZoneId()));
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
                publish(new IdentityProviderAuthenticationFailureEvent(req, req.getName(), OriginKeys.UAA, IdentityZoneHolder.getCurrentZoneId()));
                publish(new UserAuthenticationFailureEvent(user, req, IdentityZoneHolder.getCurrentZoneId()));
            } else {
                logger.debug("Password successfully matched for userId[" + user.getUsername() + "]:" + user.getId());

                boolean userMustBeVerified = !allowUnverifiedUsers || !user.isLegacyVerificationBehavior();
                if (userMustBeVerified && !user.isVerified()) {
                    publish(new UnverifiedUserAuthenticationEvent(user, req, IdentityZoneHolder.getCurrentZoneId()));
                    logger.debug("Account not verified: " + user.getId());
                    throw new AccountNotVerifiedException("Account not verified");
                }

                UaaAuthentication uaaAuthentication = new UaaAuthentication(
                        new UaaPrincipal(user),
                        user.getAuthorities(),
                        (UaaAuthenticationDetails) req.getDetails());

                uaaAuthentication.setAuthenticationMethods(Collections.singleton("pwd"));

                if (userMustUpdatePassword(user)) {
                    logger.info("Password change required for user: " + user.getEmail());
                    user.setPasswordChangeRequired(true);
                    SessionUtils.setPasswordChangeRequired(httpSession, true);
                }

                publish(new IdentityProviderAuthenticationSuccessEvent(user, uaaAuthentication, OriginKeys.UAA, IdentityZoneHolder.getCurrentZoneId()));
                return uaaAuthentication;
            }
        }

        BadCredentialsException e = new BadCredentialsException("Bad credentials");
        publish(new AuthenticationFailureBadCredentialsEvent(req, e));
        throw e;
    }

    private boolean userMustUpdatePassword(UaaUser user) {
        return user.isPasswordChangeRequired() ||
                afterPasswordExpirationDate(user.getPasswordLastModified()) ||
                afterSystemWidePasswordExpirationDate(user.getPasswordLastModified());
    }

    private boolean afterSystemWidePasswordExpirationDate(Date userPasswordLastModified) {
        Date idpPasswordPolicyNewerThan = getIdpPasswordPolicyNewerThan();
        return idpPasswordPolicyNewerThan != null && (userPasswordLastModified == null || idpPasswordPolicyNewerThan.getTime() > userPasswordLastModified.getTime());
    }

    private int getPasswordExpiresInMonths() {
        int result = 0;
        IdentityProvider provider = providerProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        if (provider != null) {
            UaaIdentityProviderDefinition idpDefinition = ObjectUtils.castInstance(provider.getConfig(), UaaIdentityProviderDefinition.class);
            if (idpDefinition != null) {
                if (null != idpDefinition.getPasswordPolicy()) {
                    return idpDefinition.getPasswordPolicy().getExpirePasswordInMonths();
                }
            }
        }
        return result;
    }

    private Date getIdpPasswordPolicyNewerThan() {
        IdentityProvider provider = providerProvisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, IdentityZoneHolder.get().getId());
        if (provider != null) {
            UaaIdentityProviderDefinition idpDefinition = ObjectUtils.castInstance(provider.getConfig(), UaaIdentityProviderDefinition.class);
            if (idpDefinition != null && idpDefinition.getPasswordPolicy() != null) {
                return idpDefinition.getPasswordPolicy().getPasswordNewerThan();
            }
        }
        return null;
    }

    private UaaUser getUaaUser(Authentication req) {
        try {
            UaaUser user = userDatabase.retrieveUserByName(req.getName().toLowerCase(Locale.US), getOrigin());
            if (user != null) {
                return user;
            }
        } catch (UsernameNotFoundException ignored) {
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

    private boolean afterPasswordExpirationDate(Date passwordLastModified) {
        int expiringPassword = getPasswordExpiresInMonths();
        if (expiringPassword > 0) {
            Calendar cal = Calendar.getInstance();
            cal.setTimeInMillis(passwordLastModified.getTime());
            cal.add(Calendar.MONTH, expiringPassword);
            return cal.getTimeInMillis() < System.currentTimeMillis();
        }
        return false;
    }
}
