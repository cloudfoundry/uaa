package org.cloudfoundry.identity.uaa.mfa;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.mfa.exception.InvalidMfaProviderException;
import org.cloudfoundry.identity.uaa.mfa.exception.MfaAlreadyExistsException;
import org.cloudfoundry.identity.uaa.mfa.exception.MfaProviderUpdateIsNotAllowed;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.MfaConfig;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static org.springframework.web.bind.annotation.RequestMethod.*;

@RequestMapping("/mfa-providers")
@RestController
public class MfaProviderEndpoints implements ApplicationEventPublisherAware{
    protected static Logger logger = LoggerFactory.getLogger(MfaProviderEndpoints.class);
    private ApplicationEventPublisher publisher;
    private MfaProviderProvisioning mfaProviderProvisioning;
    private MfaProviderValidator mfaProviderValidator;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher publisher) {
        this.publisher = publisher;
    }

    @RequestMapping(method = POST)
    public ResponseEntity<MfaProvider> createMfaProvider(@RequestBody MfaProvider body) {
        String zoneId = IdentityZoneHolder.get().getId();
        body.setIdentityZoneId(zoneId);
        mfaProviderValidator.validate(body);
        if(!StringUtils.hasText(body.getConfig().getIssuer())){
            body.getConfig().setIssuer(IdentityZoneHolder.get().getName());
        }
        MfaProvider created = mfaProviderProvisioning.create(body,zoneId);
        return new ResponseEntity<>(created, HttpStatus.CREATED);
    }

    @RequestMapping(value = "{id}", method = PUT)
    public ResponseEntity<MfaProvider> updateMfaProvider() throws MfaProviderUpdateIsNotAllowed {
        throw new MfaProviderUpdateIsNotAllowed();
    }

    @RequestMapping(method = GET)
    public ResponseEntity<List<MfaProvider>> retrieveMfaProviders() {
        String zoneId = IdentityZoneHolder.get().getId();
        List<MfaProvider> providers = mfaProviderProvisioning.retrieveAll(zoneId);
        return new ResponseEntity<>(providers, HttpStatus.OK);
    }

    @RequestMapping(value = "{id}", method = GET)
    public ResponseEntity<MfaProvider> retrieveMfaProviderById(@PathVariable String id) {
        String zoneId = IdentityZoneHolder.get().getId();
        MfaProvider provider = mfaProviderProvisioning.retrieve(id, zoneId);
        return new ResponseEntity<>(provider, HttpStatus.OK);
    }

    @RequestMapping(value = "{id}", method = DELETE)
    public ResponseEntity<MfaProvider> deleteMfaProviderById(@PathVariable String id) {
        MfaProvider existing = mfaProviderProvisioning.retrieve(id, IdentityZoneHolder.get().getId());
        MfaConfig currentMfaConfig = IdentityZoneHolder.get().getConfig().getMfaConfig();
        if(currentMfaConfig.isEnabled() && currentMfaConfig.getProviderName().equals(existing.getName())) {
            throw new MfaAlreadyExistsException("MFA provider is currently active on zone: " + IdentityZoneHolder.get().getId() + ". Please deactivate it from the zone or set another MFA provider");
        }
        publisher.publishEvent(new EntityDeletedEvent<>(existing, SecurityContextHolder.getContext().getAuthentication(), IdentityZoneHolder.getCurrentZoneId()));
        return new ResponseEntity<>(existing, HttpStatus.OK);
    }

    @ExceptionHandler(InvalidMfaProviderException.class)
    public ResponseEntity<InvalidMfaProviderException> handleInvalidMfaProviderException(InvalidMfaProviderException e) {
        return new ResponseEntity<>(e, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @ExceptionHandler(MfaAlreadyExistsException.class)
    public ResponseEntity<InvalidMfaProviderException> handleInvalidMfaProviderException(MfaAlreadyExistsException e) {
        return new ResponseEntity<>(new InvalidMfaProviderException(e.getMessage()), HttpStatus.CONFLICT);
    }


    @ExceptionHandler(EmptyResultDataAccessException.class)
    public ResponseEntity<EmptyResultDataAccessException> handleEmptyResultDataAccessException(EmptyResultDataAccessException e) {
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(MfaProviderUpdateIsNotAllowed.class)
    public ResponseEntity<MfaProviderUpdateIsNotAllowed> handleMfaUpdatingNameOfActiveProvider(MfaProviderUpdateIsNotAllowed e) {
        return new ResponseEntity<>(HttpStatus.METHOD_NOT_ALLOWED);
    }

    public MfaProviderProvisioning getMfaProviderProvisioning() {
        return mfaProviderProvisioning;
    }

    public void setMfaProviderProvisioning(MfaProviderProvisioning mfaProviderProvisioning) {
        this.mfaProviderProvisioning = mfaProviderProvisioning;
    }

    public void setMfaProviderValidator(MfaProviderValidator mfaProviderValidator) {
        this.mfaProviderValidator = mfaProviderValidator;
    }
}
