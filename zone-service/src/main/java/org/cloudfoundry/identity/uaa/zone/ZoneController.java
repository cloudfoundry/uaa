package org.cloudfoundry.identity.uaa.zone;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.NOT_FOUND;

import javax.validation.ConstraintViolationException;
import javax.validation.constraints.NotBlank;

import org.cloudfoundry.identity.uaa.zone.model.ZoneResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@Validated
@RestController("zoneEndpoints")
@RequestMapping("/zones")
public class ZoneController {

    private static final Logger logger = LoggerFactory.getLogger(ZoneController.class);
    private final ZoneService zoneService;

    public static final String MANDATORY_VALIDATION_MESSAGE = "must not be empty";

    public ZoneController(ZoneService zoneService) {
        this.zoneService = zoneService;
    }

    @GetMapping
    public ResponseEntity<ZoneResponse> getZone(@NotBlank(message = MANDATORY_VALIDATION_MESSAGE) @RequestParam String name) {
        return new ResponseEntity<>(zoneService.getZoneDetails(name), HttpStatus.ACCEPTED);
    }

    @ExceptionHandler(ZoneDoesNotExistsException.class)
    public ResponseEntity<String> handleZoneDoesNotExistsException(ZoneDoesNotExistsException e) {
        return new ResponseEntity<>("{\"message\", \""+ e.getMessage() +"\" }", NOT_FOUND);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<String> handleMessageReadableException(HttpMessageNotReadableException e) {
        return new ResponseEntity<>("{\"message\",\"Request failed due to a validation error.\" }", BAD_REQUEST);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<String> handleValidationException(MethodArgumentNotValidException e) {
        return new ResponseEntity<>("{\"message\", \""+ e.getMessage() +"\" }", BAD_REQUEST);
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<String> handleMissingRequestParamException(MissingServletRequestParameterException e) {
        return new ResponseEntity<>("{\"message\", \""+ e.getMessage() +"\" }", BAD_REQUEST);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<String> handleConstraintViolationException(ConstraintViolationException e) {
        return new ResponseEntity<>("{\"message\", \""+ e.getMessage() +"\" }", BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e) {
        logger.error(e.getClass() + ": " + e.getMessage(), e);
        return new ResponseEntity<>("{\"message\",\"Server Error.\" }", INTERNAL_SERVER_ERROR);
    }

}
