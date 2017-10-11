package org.cloudfoundry.identity.uaa.mfa_provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import java.util.List;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RequestMapping("/mfa-providers")
@RestController
public class MfaProviderEndpoints implements ApplicationEventPublisherAware{
    protected static Log logger = LogFactory.getLog(MfaProviderEndpoints.class);
    private ApplicationEventPublisher publisher;
    private MfaProviderProvisioning mfaProviderProvisioning;
    private MfaProviderValidator mfaProviderValidator;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    @RequestMapping(method = POST)
    public ResponseEntity<MfaProvider> createMfaProvider(@RequestBody MfaProvider provider) {
        String zoneId = IdentityZoneHolder.get().getId();
        provider.setIdentityZoneId(zoneId);
        mfaProviderValidator.validate(provider);
        if(!StringUtils.hasText(provider.getConfig().getIssuer())){
            provider.getConfig().setIssuer(IdentityZoneHolder.get().getName());
        }
        MfaProvider created = mfaProviderProvisioning.create(provider,zoneId);
        return new ResponseEntity<>(created, HttpStatus.CREATED);
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
