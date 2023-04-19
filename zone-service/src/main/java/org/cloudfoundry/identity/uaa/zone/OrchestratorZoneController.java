package org.cloudfoundry.identity.uaa.zone;

import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.MANDATORY_VALIDATION_MESSAGE;
import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.getErrorMessagesConstraintViolation;
import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.getErrorMessagesHttpMessageNotReadable;
import static org.cloudfoundry.identity.uaa.zone.ErrorMessageUtil.getErrorMessagesMethodArgumentInvalid;
import static org.springframework.http.HttpStatus.ACCEPTED;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.METHOD_NOT_ALLOWED;
import static org.springframework.http.HttpStatus.NOT_FOUND;

import javax.naming.OperationNotSupportedException;
import javax.validation.ConstraintViolationException;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;

import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.annotation.Transactional;
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

@Validated
@RestController("zoneEndpoints")
@RequestMapping("/orchestrator/zones")
public class OrchestratorZoneController {

    public static final String GET_ZONE_PREFIX = "getZone.";
    private static final Logger logger = LoggerFactory.getLogger(OrchestratorZoneController.class);
    private final OrchestratorZoneService zoneService;

    public OrchestratorZoneController(OrchestratorZoneService zoneService) {
        this.zoneService = zoneService;
    }

    @GetMapping
    @Transactional(readOnly = true)
    public ResponseEntity<OrchestratorZoneResponse> getZone(@NotBlank(message = MANDATORY_VALIDATION_MESSAGE) @RequestParam String name) {
        return ResponseEntity.ok(zoneService.getZoneDetails(name));
    }

    @PostMapping
    @Transactional
    public ResponseEntity<OrchestratorZoneResponse> createOrchestratorZone(
        @RequestBody @Valid OrchestratorZoneRequest orchestratorZoneRequest) {
        return ResponseEntity.status(ACCEPTED).body(zoneService.createZone(orchestratorZoneRequest));
    }

    @DeleteMapping
    @Transactional
    public ResponseEntity<?> deleteZone(@NotBlank(message = MANDATORY_VALIDATION_MESSAGE) @RequestParam String name) {
        return ResponseEntity.status(ACCEPTED).body(zoneService.deleteZone(name));
    }

    @PutMapping
    public ResponseEntity<?> updateZone(@RequestBody OrchestratorZoneRequest zoneRequest) throws OperationNotSupportedException {
        throw new OperationNotSupportedException("Put Operation not Supported");
    }

    @ExceptionHandler(value = {
        MissingServletRequestParameterException.class,
        OrchestratorZoneServiceException.class
    })
    public ResponseEntity<OrchestratorZoneResponse> badRequest(Exception ex) {
        String zoneName = null;
        if (ex instanceof OrchestratorZoneServiceException) {
            zoneName = ((OrchestratorZoneServiceException) ex).getZoneName();
        }

        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setName(zoneName);
        response.setMessage(ex.getMessage());
        response.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(value = { ZoneAlreadyExistsException.class })
    public ResponseEntity<OrchestratorZoneResponse> zoneAlreadyExist(ZoneAlreadyExistsException ex) {
        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setName(ex.getZoneName());
        response.setMessage(ex.getMessage());
        response.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        return ResponseEntity.status(CONFLICT).body(response);
    }

    @ExceptionHandler(value = { ZoneDoesNotExistsException.class })
    public ResponseEntity<OrchestratorZoneResponse> notFound(ZoneDoesNotExistsException ex) {
        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setName(ex.getZoneName());
        response.setMessage(ex.getMessage());
        response.setState(OrchestratorState.NOT_FOUND.toString());

        return ResponseEntity.status(NOT_FOUND).body(response);
    }

    @ExceptionHandler(value = { AccessDeniedException.class })
    public ResponseEntity<OrchestratorZoneResponse> accessDenied(Exception ex) {
        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setMessage(ex.getMessage());
        response.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        return ResponseEntity.status(FORBIDDEN).body(response);
    }

    @ExceptionHandler(value = { OperationNotSupportedException.class })
    public ResponseEntity<OrchestratorZoneResponse> methodNotAllowed(Exception ex) {
        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setMessage(ex.getMessage());
        response.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        return ResponseEntity.status(METHOD_NOT_ALLOWED).body(response);
    }

    @ExceptionHandler(value = { Exception.class })
    public ResponseEntity<OrchestratorZoneResponse> internalServerError(Exception ex) {
        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setMessage(ex.getMessage());
        response.setState(OrchestratorState.SERVER_FAILURE.toString());

        return ResponseEntity.status(INTERNAL_SERVER_ERROR).body(response);
    }

    @ExceptionHandler(value = { HttpMessageNotReadableException.class })
    public ResponseEntity<OrchestratorZoneResponse> messageReadableException(HttpMessageNotReadableException ex) {
        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setMessage(getErrorMessagesHttpMessageNotReadable(ex));
        response.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(value = { MethodArgumentNotValidException.class })
    public ResponseEntity<OrchestratorZoneResponse> methodArgumentException(MethodArgumentNotValidException ex) {
        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setName(ErrorMessageUtil.getNameFromException(ex));
        response.setMessage(getErrorMessagesMethodArgumentInvalid(ex));
        response.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        return ResponseEntity.badRequest().body(response);
    }

    @ExceptionHandler(value = { ConstraintViolationException.class })
    public ResponseEntity<OrchestratorZoneResponse> constraintViolationException(ConstraintViolationException ex) {
        OrchestratorZoneResponse response = new OrchestratorZoneResponse();
        response.setMessage(getErrorMessagesConstraintViolation(ex));
        response.setState(OrchestratorState.PERMANENT_FAILURE.toString());

        return ResponseEntity.badRequest().body(response);
    }
}
