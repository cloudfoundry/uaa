package org.cloudfoundry.identity.uaa.zone;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.ConstraintViolation;
import javax.validation.ConstraintViolationException;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.util.CollectionUtils;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.validation.ObjectError;
import org.springframework.web.bind.MethodArgumentNotValidException;

public class ErrorMessageUtil {

    public static final String ADMIN_CLIENT_CREDENTIALS_CANNOT_CONTAIN_SPACES_OR_BLANK =
        "field cannot contain spaces or cannot be blank.";
    public static final String MANDATORY_VALIDATION_MESSAGE = "must be specified";
    public static final String ADMIN_CLIENT_CREDENTIALS_VALIDATION_PATTERN = "^\\p{Graph}+$";
    public static final String ADMIN_CLIENT_CREDENTIALS_VALIDATION_MESSAGE = "must not be empty and must not have empty " +
                                                                             "spaces";
    public static final String UAA_CUSTOM_SUBDOMAIN_PATTERN = "(?:[A-Za-z0-9][A-Za-z0-9\\-]{0,61}[A-Za-z0-9]|[A-Za-z0-9])";
    public static final String UAA_CUSTOM_SUBDOMAIN_MESSAGE = "is invalid. Special characters are not allowed in the " +
                                                              "subdomain name except hyphen which can be specified in the middle";

    public static final String INVALID_FORMAT_ERROR_MESSAGE = "Request failed due to a validation error";

    public static final String getAffectedProperty(ObjectError objectError) {
        return objectError instanceof FieldError ? ((FieldError)objectError).getField() : objectError.getObjectName();
    }
    public static final String getErrorMessagesConstraintViolation(ConstraintViolationException ex) {
        Set<String> errorMessages = new HashSet<>();
        for (ConstraintViolation<?> violation : ex.getConstraintViolations()) {
            String parameter = violation.getPropertyPath().toString();
            errorMessages.add(parameter.substring(parameter.indexOf(".")+1) + " " + violation.getMessage());
        }
        return String.join("; ", errorMessages);
    }

    public static final String getErrorMessagesMethodArgumentInvalid(MethodArgumentNotValidException ex) {
        BindingResult bindingResult = ex.getBindingResult();
        Set<String> errorMessages = new HashSet<>();
        for (ObjectError objectError: bindingResult.getAllErrors()) {
            String message = ErrorMessageUtil.getAffectedProperty(objectError) + " "+ objectError.getDefaultMessage();
            errorMessages.add(message);
        }
        return String.join("; ", errorMessages);
    }

    public static final String getErrorMessagesHttpMessageNotReadable(HttpMessageNotReadableException exception) {
        String errorMessage = INVALID_FORMAT_ERROR_MESSAGE;
        Throwable cause = exception.getCause();
        if (cause instanceof JsonParseException) {
            JsonParseException jsonParseException = (JsonParseException) cause;
            errorMessage = jsonParseException.getOriginalMessage();
        } else if (cause instanceof JsonMappingException) {
            JsonMappingException jsonMappingException = (JsonMappingException) cause;
            if (!CollectionUtils.isEmpty(jsonMappingException.getPath())) {
                errorMessage = jsonMappingException.getOriginalMessage();
                errorMessage = getErrorMessage(errorMessage, jsonMappingException);
            }
        } else if (cause == null) {
            errorMessage = exception.getMessage();
        }
        return errorMessage;
    }

    private static String getErrorMessage(final String errorMessage, JsonMappingException jsonMappingException) {
        return jsonMappingException.getPath().stream().map(
            error -> error.getFieldName() + " is invalid: " + errorMessage).collect(Collectors.joining("; "));
    }
}
