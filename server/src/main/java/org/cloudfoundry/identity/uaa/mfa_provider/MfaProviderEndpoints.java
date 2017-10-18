package org.cloudfoundry.identity.uaa.mfa_provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.mfa_provider.exception.InvalidMfaProviderException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
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

import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

@RequestMapping("/mfa-providers")
@RestController
public class MfaProviderEndpoints implements ApplicationEventPublisherAware{
    protected static Log logger = LogFactory.getLog(MfaProviderEndpoints.class);
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
    public ResponseEntity<MfaProvider> updateMfaProvider(@PathVariable String id, @RequestBody MfaProvider body) {
        String zoneId = IdentityZoneHolder.get().getId();
        mfaProviderProvisioning.retrieve(id, zoneId);
        body.setId(id);
        body.setIdentityZoneId(zoneId);
        mfaProviderValidator.validate(body);

        MfaProvider updated = mfaProviderProvisioning.update(body, zoneId);
        return new ResponseEntity<>(updated, HttpStatus.OK);
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
        publisher.publishEvent(new EntityDeletedEvent<>(existing, SecurityContextHolder.getContext().getAuthentication()));
        return new ResponseEntity<>(existing, HttpStatus.OK);
    }

    @ExceptionHandler(InvalidMfaProviderException.class)
    public ResponseEntity<InvalidMfaProviderException> handleInvalidMfaProviderException(InvalidMfaProviderException e) {
        return new ResponseEntity<>(e, HttpStatus.UNPROCESSABLE_ENTITY);
    }

    @ExceptionHandler(EmptyResultDataAccessException.class)
    public ResponseEntity<EmptyResultDataAccessException> handleEmptyResultDataAccessException(EmptyResultDataAccessException e) {
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
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
