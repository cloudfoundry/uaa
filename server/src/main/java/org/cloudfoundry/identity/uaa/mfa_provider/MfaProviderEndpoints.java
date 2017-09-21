package org.cloudfoundry.identity.uaa.mfa_provider;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RequestMapping("/mfa-providers")
@RestController
public class MfaProviderEndpoints implements ApplicationEventPublisherAware{
    protected static Log logger = LogFactory.getLog(MfaProviderEndpoints.class);
    private ApplicationEventPublisher publisher;

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        this.publisher = applicationEventPublisher;
    }

    @RequestMapping(method = POST)
    public ResponseEntity<MfaProvider> createMfaProvider(MfaProvider provider) {
        provider.validate();
        return null;
    }
}
