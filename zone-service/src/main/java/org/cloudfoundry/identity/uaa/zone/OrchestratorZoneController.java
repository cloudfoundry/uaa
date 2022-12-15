package org.cloudfoundry.identity.uaa.zone;

import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.METHOD_NOT_ALLOWED;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.FORBIDDEN;

import java.io.IOException;
import javax.naming.OperationNotSupportedException;
import javax.validation.ConstraintViolationException;
import javax.validation.constraints.NotBlank;
import javax.validation.Valid;

import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.access.AccessDeniedException;


@Validated
@RestController("zoneEndpoints")
@RequestMapping("/orchestrator/zones")
public class OrchestratorZoneController {

    private static final Logger logger = LoggerFactory.getLogger(OrchestratorZoneController.class);
    private final OrchestratorZoneService zoneService;

    public static final String MANDATORY_VALIDATION_MESSAGE = "must not be empty";

    public OrchestratorZoneController(OrchestratorZoneService zoneService) {
        this.zoneService = zoneService;
    }

    @GetMapping
    public ResponseEntity<OrchestratorZoneResponse> getZone(@NotBlank(message = MANDATORY_VALIDATION_MESSAGE) @RequestParam String name) {
        return new ResponseEntity<>(zoneService.getZoneDetails(name), HttpStatus.OK);
    }

    @PostMapping
    public ResponseEntity<?> createOrchestratorZone(@RequestBody @Valid OrchestratorZoneRequest orchestratorZoneRequest )
        throws OrchestratorZoneServiceException, IOException {
        zoneService.createZone(orchestratorZoneRequest);
        return new ResponseEntity<>("", HttpStatus.ACCEPTED);
    }

    @DeleteMapping
    public ResponseEntity<?> deleteZone(@NotBlank(message = MANDATORY_VALIDATION_MESSAGE) @RequestParam String name) {
        return zoneService.deleteZone(name);
    }

    @PutMapping
    public ResponseEntity<?> updateZone(@RequestBody OrchestratorZoneRequest zoneRequest) throws OperationNotSupportedException {
        throw new OperationNotSupportedException("Put Operation not Supported");
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

    @ExceptionHandler(OperationNotSupportedException.class)
    public ResponseEntity<String> handleOperationNotSupportedException(OperationNotSupportedException e) {
        return new ResponseEntity<>("{\"message\", \""+ e.getMessage() +"\" }", METHOD_NOT_ALLOWED);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<String> handleAccessDeniedException(AccessDeniedException e) {
        return new ResponseEntity<>("{\"message\", \""+ e.getMessage() +"\" }", FORBIDDEN);
    }

    @ExceptionHandler(ZoneAlreadyExistsException.class)
    public ResponseEntity<String> handleZoneAlreadyExistsException(ZoneAlreadyExistsException e) {
        return new ResponseEntity<>("{\"message\", \""+ e.getMessage() +"\" }", BAD_REQUEST);
    }

    @ExceptionHandler(OrchestratorZoneServiceException.class)
    public ResponseEntity<String> handleOrchestratorZoneServiceException(OrchestratorZoneServiceException e) {
        return new ResponseEntity<>("{\"message\", \""+ e.getMessage() +"\" }", BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleException(Exception e) {
        logger.error(e.getClass() + ": " + e.getMessage(), e);
        return new ResponseEntity<>("{\"message\", \""+ e.getMessage() +"\" }", INTERNAL_SERVER_ERROR);
    }
}
