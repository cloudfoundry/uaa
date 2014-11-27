package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;

import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.web.bind.annotation.RequestMethod.*;

@RestController
@RequestMapping("/identity-zones")
public class IdentityZoneEndpoints {

    private IdentityZoneProvisioning zoneDao;
    private IdentityProviderProvisioning idpDao;

    @RequestMapping(value="{id}", method = PUT)
    public ResponseEntity<Void> createOrUpdateIdentityZone(@RequestBody @Valid IdentityZone zone, @PathVariable String id) {
        zone.setId(id);
        IdentityZone created = zoneDao.create(zone);
        IdentityZone previous = IdentityZoneHolder.get();
        IdentityZoneHolder.set(created);
        IdentityProvider defaultIdp = new IdentityProvider();
        defaultIdp.setName("internal");
        defaultIdp.setType("internal");
        defaultIdp.setOriginKey(Origin.UAA);
        idpDao.create(defaultIdp);
        IdentityZoneHolder.set(previous);
        return new ResponseEntity<Void>(CREATED);
    }

    public void setIdentityZoneProvisioning(IdentityZoneProvisioning dao) {
        this.zoneDao = dao;
    }

    @ExceptionHandler(ZoneAlreadyExistsException.class)
    public ResponseEntity<IdentityZone> handleZoneAlreadyExistsException() {
        return new ResponseEntity<>(CONFLICT);
    }

    public void setIdentityProviderProvisioning(IdentityProviderProvisioning idpDao) {
        this.idpDao = idpDao;
    }
}
