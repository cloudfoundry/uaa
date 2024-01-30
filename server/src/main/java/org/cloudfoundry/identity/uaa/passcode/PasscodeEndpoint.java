package org.cloudfoundry.identity.uaa.passcode;

import java.security.Principal;
import java.sql.Timestamp;
import java.time.Duration;
import java.util.Map;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.login.LoginInfoEndpoint;
import org.cloudfoundry.identity.uaa.provider.saml.LoginSamlAuthenticationToken;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

/**
 * Controller that sends login info (e.g. prompts) to clients wishing to
 * authenticate.
 */
@Controller
public class PasscodeEndpoint {

    public static final String PASSCODE = "passcode";
    private static Logger logger = LoggerFactory.getLogger(PasscodeEndpoint.class);
    private static final Duration CODE_EXPIRATION = Duration.ofMinutes(5L);

    private final ExpiringCodeStore expiringCodeStore;

    public PasscodeEndpoint(
            final @Qualifier("codeStore") ExpiringCodeStore expiringCodeStore) {
        this.expiringCodeStore = expiringCodeStore;
    }

    @RequestMapping(value = {"/passcode"}, method = GET)
    public String generatePasscode(Map<String, Object> model, Principal principal) {
        String username;
        String origin;
        String userId;
        Map<String, Object> authorizationParameters = null;

        UaaPrincipal uaaPrincipal;
        if (principal instanceof UaaPrincipal) {
            uaaPrincipal = (UaaPrincipal) principal;
            username = uaaPrincipal.getName();
        } else if (principal instanceof UaaAuthentication) {
            uaaPrincipal = ((UaaAuthentication) principal).getPrincipal();
            username = uaaPrincipal.getName();
        } else if (principal instanceof final LoginSamlAuthenticationToken samlTokenPrincipal) {
            uaaPrincipal = samlTokenPrincipal.getUaaPrincipal();
            username = principal.getName();
        } else if (principal instanceof Authentication && ((Authentication) principal).getPrincipal() instanceof UaaPrincipal) {
            uaaPrincipal = (UaaPrincipal) ((Authentication) principal).getPrincipal();
            username = uaaPrincipal.getName();
        } else {
            throw new LoginInfoEndpoint.UnknownPrincipalException();
        }
        origin = uaaPrincipal.getOrigin();
        userId = uaaPrincipal.getId();

        PasscodeInformation pi = new PasscodeInformation(userId, username, null, origin, authorizationParameters);

        String intent = ExpiringCodeType.PASSCODE + " " + pi.getUserId();

        expiringCodeStore.expireByIntent(intent, IdentityZoneHolder.get().getId());

        ExpiringCode code = expiringCodeStore.generateCode(
                JsonUtils.writeValueAsString(pi),
                new Timestamp(System.currentTimeMillis() + CODE_EXPIRATION.toMillis()),
                intent, IdentityZoneHolder.get().getId());

        model.put(PASSCODE, code.getCode());

        return PASSCODE;
    }
}
