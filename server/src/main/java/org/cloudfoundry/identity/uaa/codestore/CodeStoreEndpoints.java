package org.cloudfoundry.identity.uaa.codestore;

import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.View;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class CodeStoreEndpoints {

    private final ExpiringCodeStore expiringCodeStore;
    private final HttpMessageConverter<?>[] messageConverters;
    private final IdentityZoneManager identityZoneManager;

    CodeStoreEndpoints(
            final ExpiringCodeStore expiringCodeStore,
            final HttpMessageConverter<?>[] messageConverters,
            final IdentityZoneManager identityZoneManager) {
        this.expiringCodeStore = expiringCodeStore;
        this.messageConverters = messageConverters;
        this.identityZoneManager = identityZoneManager;
    }

    @PostMapping({"/Codes"})
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    public ExpiringCode generateCode(@RequestBody ExpiringCode expiringCode) {
        try {
            return expiringCodeStore.generateCode(expiringCode.getData(), expiringCode.getExpiresAt(), null, identityZoneManager.getCurrentIdentityZoneId());
        } catch (NullPointerException e) {
            throw new CodeStoreException("data and expiresAt are required.", HttpStatus.BAD_REQUEST);
        } catch (IllegalArgumentException e) {
            throw new CodeStoreException("expiresAt must be in the future.", HttpStatus.BAD_REQUEST);
        } catch (DataIntegrityViolationException e) {
            throw new CodeStoreException("Duplicate code generated.", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/Codes/{code}")
    @ResponseBody
    public ExpiringCode retrieveCode(@PathVariable String code) {
        ExpiringCode result;
        try {
            result = expiringCodeStore.retrieveCode(code, identityZoneManager.getCurrentIdentityZoneId());
        } catch (NullPointerException e) {
            throw new CodeStoreException("code is required.", HttpStatus.BAD_REQUEST);
        }

        if (result == null) {
            throw new CodeStoreException("Code not found: " + code, HttpStatus.NOT_FOUND);
        }

        return result;
    }

    @ExceptionHandler
    public View handleException(Exception t, HttpServletRequest request) throws CodeStoreException {
        CodeStoreException e = new CodeStoreException("Unexpected error", t, HttpStatus.INTERNAL_SERVER_ERROR);
        if (t instanceof CodeStoreException exception) {
            e = exception;
        }
        // User can supply trace=true or just trace (unspecified) to get stack
        // traces
        boolean trace = request.getParameter("trace") != null && !"false".equals(request.getParameter("trace"));
        return new ConvertingExceptionView(new ResponseEntity<>(new ExceptionReport(e, trace),
                e.getStatus()), messageConverters);
    }
}
