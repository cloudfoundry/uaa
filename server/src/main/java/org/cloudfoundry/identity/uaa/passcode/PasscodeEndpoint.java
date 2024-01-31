package org.cloudfoundry.identity.uaa.passcode;

import java.security.Principal;
import java.sql.Timestamp;
import java.time.Duration;
import java.util.Map;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;

import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.springframework.web.bind.annotation.RequestMethod.GET;

/**
 * Controller that generates passcodes
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
        Map<String, Object> authorizationParameters = null;

        final PasscodeInformation passcodeInformation = new PasscodeInformation(principal, authorizationParameters);
        String intent = ExpiringCodeType.PASSCODE + " " + passcodeInformation.getUserId();

        expiringCodeStore.expireByIntent(intent, IdentityZoneHolder.get().getId());

        ExpiringCode code = expiringCodeStore.generateCode(
                JsonUtils.writeValueAsString(passcodeInformation),
                new Timestamp(System.currentTimeMillis() + CODE_EXPIRATION.toMillis()),
                intent,
                IdentityZoneHolder.get().getId());

        model.put(PASSCODE, code.getCode());

        return PASSCODE;
    }

    @ResponseStatus(value = HttpStatus.FORBIDDEN, reason = "Unknown authentication token type, unable to derive user ID.")
    public static final class UnknownPrincipalException extends RuntimeException {
    }
}
