package org.cloudfoundry.identity.uaa.zone;

import java.util.ArrayList;
import java.util.List;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.oauth.ClientAdminEndpoints;
import org.cloudfoundry.identity.uaa.oauth.ClientDetailsValidator;
import org.cloudfoundry.identity.uaa.oauth.InvalidClientDetailsException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.web.bind.MethodArgumentNotValidException;
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

    private static final Logger log = LoggerFactory.getLogger(IdentityZoneEndpoints.class);
    private final IdentityZoneProvisioning zoneDao;
    private final IdentityProviderProvisioning idpDao;
    private final ClientRegistrationService clientRegistrationService;
    private final ClientDetailsValidator clientDetailsValidator;
    
    
    public IdentityZoneEndpoints(IdentityZoneProvisioning zoneDao, IdentityProviderProvisioning idpDao, ClientRegistrationService clientRegistrationService, ClientDetailsValidator clientDetailsValidator) {
        super();
        this.zoneDao = zoneDao;
        this.idpDao = idpDao;
        this.clientRegistrationService = clientRegistrationService;
        this.clientDetailsValidator = clientDetailsValidator;
    }

    
    @RequestMapping(value = "{id}", method = PUT)
    public ResponseEntity<Void> createOrUpdateIdentityZone(@RequestBody @Valid IdentityZoneCreationRequest body,
            @PathVariable String id) {
        IdentityZone previous = IdentityZoneHolder.get();
        try {
     
        	List<ClientDetails> clients = new ArrayList<ClientDetails>();
        	if (body.getClientDetails() != null) {
        		for (BaseClientDetails clientDetails : body.getClientDetails()) {
        			if (clientDetails != null) {
        				clients.add(clientDetailsValidator.validate(clientDetails, true, false));
        			}
				}
        	}
        	body.getIdentityZone().setId(id);
            IdentityZone created = zoneDao.create(body.getIdentityZone());
            IdentityZoneHolder.set(created);
            IdentityProvider defaultIdp = new IdentityProvider();
            defaultIdp.setName("internal");
            defaultIdp.setType("internal");
            defaultIdp.setOriginKey(Origin.UAA);
            idpDao.create(defaultIdp);

            for (ClientDetails validClient : clients) {
            	clientRegistrationService.addClientDetails(validClient);
			}
            
            return new ResponseEntity<Void>(CREATED);
        } finally {
            IdentityZoneHolder.set(previous);
        }
    }
    
	@ExceptionHandler(ZoneAlreadyExistsException.class)
    public ResponseEntity<ZoneAlreadyExistsException> handleZoneAlreadyExistsException(ZoneAlreadyExistsException e) {
        return new ResponseEntity<>(e,CONFLICT);
    }
	
    @ExceptionHandler(InvalidClientDetailsException.class)
    public ResponseEntity<InvalidClientDetailsException> handleInvalidClientDetails(InvalidClientDetailsException e) {
        return new ResponseEntity<InvalidClientDetailsException>(e, HttpStatus.BAD_REQUEST);
    }
    
    @ExceptionHandler(MethodArgumentNotValidException.class) 
    public ResponseEntity<Void> handleValidationException(MethodArgumentNotValidException e) {
    	return new ResponseEntity<Void>(HttpStatus.BAD_REQUEST);
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Void> handleException(Exception e) {
    	log.error(e.getClass()+": "+e.getMessage(),e);
    	return new ResponseEntity<Void>(HttpStatus.INTERNAL_SERVER_ERROR);
    }

}
