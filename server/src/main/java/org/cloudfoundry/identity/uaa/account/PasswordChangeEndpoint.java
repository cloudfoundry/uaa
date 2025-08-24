package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.resources.ActionResult;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.cloudfoundry.identity.uaa.web.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.View;

import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;

@Controller
public class PasswordChangeEndpoint {

    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final IdentityZoneManager identityZoneManager;
    private final PasswordValidator passwordValidator;
    private final ScimUserProvisioning scimUserProvisioning;
    private final HttpMessageConverter<?>[] messageConverters;
    private final SecurityContextAccessor securityContextAccessor;

    public PasswordChangeEndpoint(final IdentityZoneManager identityZoneManager,
            final PasswordValidator passwordValidator,
            final ScimUserProvisioning scimUserProvisioning,
            final SecurityContextAccessor securityContextAccessor) {
        this.identityZoneManager = identityZoneManager;
        this.passwordValidator = passwordValidator;
        this.scimUserProvisioning = scimUserProvisioning;
        this.messageConverters = new HttpMessageConverter<?>[]{
                new ExceptionReportHttpMessageConverter(),
                new MappingJackson2HttpMessageConverter()
        };
        this.securityContextAccessor = securityContextAccessor;
    }

    @PutMapping("/Users/{userId}/password")
    @ResponseBody
    public ActionResult changePassword(@PathVariable String userId, @RequestBody PasswordChangeRequest change) {
        String zoneId = identityZoneManager.getCurrentIdentityZoneId();
        String oldPassword = change.getOldPassword();
        String newPassword = change.getPassword();

        throwIfPasswordChangeNotPermitted(userId, oldPassword, zoneId);
        if (scimUserProvisioning.checkPasswordMatches(userId, newPassword, zoneId)) {
            throw new InvalidPasswordException("Your new password cannot be the same as the old password.", UNPROCESSABLE_ENTITY);
        }
        passwordValidator.validate(newPassword);
        scimUserProvisioning.changePassword(userId, oldPassword, newPassword, zoneId);
        return new ActionResult("ok", "password updated");
    }

    @ExceptionHandler
    public View handleException(ScimResourceNotFoundException e) {
        // There's no point throwing BadCredentialsException here because it is
        // caught and
        // logged (then ignored) by the caller.
        return new ConvertingExceptionView(
                new ResponseEntity<>(new ExceptionReport(
                                new BadCredentialsException("Invalid password change request"), false),
                        HttpStatus.UNAUTHORIZED),
                messageConverters);
    }

    @ExceptionHandler(ScimException.class)
    public View handleException(ScimException e) {
        // No need to log the underlying exception (it will be logged by the
        // caller)
        return makeConvertingExceptionView(new BadCredentialsException("Invalid password change request"), e.getStatus());
    }

    @ExceptionHandler(InvalidPasswordException.class)
    public View handleException(InvalidPasswordException t) throws ScimException {
        return makeConvertingExceptionView(t, t.getStatus());
    }

    private ConvertingExceptionView makeConvertingExceptionView(Exception exceptionToWrap, HttpStatus status) {
        return new ConvertingExceptionView(new ResponseEntity<>(new ExceptionReport(
                        exceptionToWrap, false), status),
                messageConverters);
    }

    private void throwIfPasswordChangeNotPermitted(String userId, String oldPassword, String zoneId) {
        if (securityContextAccessor.isClient()) {
            // Trusted client (not acting on behalf of user)
        } else if (securityContextAccessor.isAdmin()) {
            if (userId.equals(currentUser()) && !StringUtils.hasText(oldPassword)) {
                throw new InvalidPasswordException("Previous password is required even for admin");
            }
        } else {
            String currentUserId = currentUser();
            if (!userId.equals(currentUserId)) {
                logger.warn("User with id {} attempting to change password for user {}", currentUserId, userId);
                throw new InvalidPasswordException("Not permitted to change another user's password");
            }

            if (!StringUtils.hasText(oldPassword)) {
                throw new InvalidPasswordException("Previous password is required");
            }

            if (!scimUserProvisioning.checkPasswordMatches(userId, oldPassword, zoneId)) {
                throw new BadCredentialsException("Old password is incorrect");
            }
        }
    }

    private String currentUser() {
        return securityContextAccessor.getUserId();
    }
}
