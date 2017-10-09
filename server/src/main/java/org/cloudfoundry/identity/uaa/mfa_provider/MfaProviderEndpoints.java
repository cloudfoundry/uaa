package org.cloudfoundry.identity.uaa.mfa_provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;
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

    public MfaProviderProvisioning getMfaProviderProvisioning() {
        return mfaProviderProvisioning;
    }

    public void setMfaProviderProvisioning(MfaProviderProvisioning mfaProviderProvisioning) {
        this.mfaProviderProvisioning = mfaProviderProvisioning;
    }

    public void setMfaProviderValidator(MfaProviderValidator mfaProviderValidator) {
        this.mfaProviderValidator = mfaProviderValidator;
    }

    @ExceptionHandler(InvalidMfaProviderException.class)
    public ResponseEntity<InvalidMfaProviderException> handleInvalidMfaProviderException(InvalidMfaProviderException e) {
        return new ResponseEntity<>(e, HttpStatus.UNPROCESSABLE_ENTITY);
    }
}
