package org.cloudfoundry.identity.uaa.zone;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/identity-providers")
@RestController
public class IdentityProviderEndpoints {

    private final IdentityProviderProvisioning identityProviderProvisioning;

    public IdentityProviderEndpoints(IdentityProviderProvisioning identityProviderProvisioning) {
        this.identityProviderProvisioning = identityProviderProvisioning;
    }

    @RequestMapping(method = RequestMethod.POST)
    public ResponseEntity<IdentityProvider> createIdentityProvider(@RequestBody IdentityProvider body) {

        IdentityProvider createdIdp = identityProviderProvisioning.create(body);
        return new ResponseEntity<>(createdIdp, HttpStatus.CREATED);
    }

}
