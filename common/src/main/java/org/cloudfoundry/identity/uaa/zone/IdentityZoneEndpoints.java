package org.cloudfoundry.identity.uaa.zone;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RestController
@RequestMapping("/identity-zones")
public class IdentityZoneEndpoints {

    private IdentityZoneProvisioning dao;

    @RequestMapping(method = POST)
    @ResponseStatus(CREATED)
    public IdentityZone createIdentityZone(@RequestBody @Valid IdentityZone zone) {
        return dao.create(zone);
    }

    public void setIdentityZoneProvisioning(IdentityZoneProvisioning dao) {
        this.dao = dao;
    }

    @ExceptionHandler(ZoneAlreadyExistsException.class)
    public ResponseEntity<IdentityZone> handleZoneAlreadyExistsException() {
        return new ResponseEntity<>(CONFLICT);
    }
}
