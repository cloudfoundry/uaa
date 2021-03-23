package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProvider;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderConfigurator;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlServiceProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.saml.idp.SamlSpAlreadyExistsException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.HttpStatus.UNPROCESSABLE_ENTITY;
import static org.springframework.web.bind.annotation.RequestMethod.DELETE;
import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;
import static org.springframework.web.bind.annotation.RequestMethod.PUT;

@RequestMapping("/saml/service-providers")
@RestController
public class SamlServiceProviderEndpoints {

    protected static Logger logger = LoggerFactory.getLogger(SamlServiceProviderEndpoints.class);

    private final SamlServiceProviderProvisioning serviceProviderProvisioning;
    private final SamlServiceProviderConfigurator samlConfigurator;

    public SamlServiceProviderEndpoints(
            final @Qualifier("serviceProviderProvisioning") SamlServiceProviderProvisioning serviceProviderProvisioning,
            final @Qualifier("spMetaDataProviders") SamlServiceProviderConfigurator samlConfigurator) {
        this.serviceProviderProvisioning = serviceProviderProvisioning;
        this.samlConfigurator = samlConfigurator;
    }

    @RequestMapping(method = POST)
    public ResponseEntity<SamlServiceProvider> createServiceProvider(@RequestBody SamlServiceProvider body)
            throws MetadataProviderException {
        String zoneId = IdentityZoneHolder.get().getId();
        body.setIdentityZoneId(zoneId);
        samlConfigurator.validateSamlServiceProvider(body);
        SamlServiceProvider createdSp = serviceProviderProvisioning.create(body, zoneId);
        return new ResponseEntity<>(createdSp, HttpStatus.CREATED);
    }

    @RequestMapping(value = "{id}", method = PUT)
    public ResponseEntity<SamlServiceProvider> updateServiceProvider(@PathVariable String id,
                                                                     @RequestBody SamlServiceProvider body) throws MetadataProviderException {
        SamlServiceProvider existing = serviceProviderProvisioning.retrieve(id, IdentityZoneHolder.get().getId());
        String zoneId = IdentityZoneHolder.get().getId();
        body.setId(id);
        body.setIdentityZoneId(zoneId);
        if (!body.configIsValid()) {
            return new ResponseEntity<>(UNPROCESSABLE_ENTITY);
        }
        body.setEntityId(existing.getEntityId());

        samlConfigurator.validateSamlServiceProvider(body);

        SamlServiceProvider updatedSp = serviceProviderProvisioning.update(body, zoneId);
        return new ResponseEntity<>(updatedSp, OK);
    }

    @RequestMapping(method = GET)
    public ResponseEntity<List<SamlServiceProvider>> retrieveServiceProviders(
            @RequestParam(value = "active_only", required = false) String activeOnly) {
        boolean retrieveActiveOnly = Boolean.parseBoolean(activeOnly);
        List<SamlServiceProvider> serviceProviderList =
                serviceProviderProvisioning.retrieveAll(retrieveActiveOnly,
                        IdentityZoneHolder.get().getId());
        return new ResponseEntity<>(serviceProviderList, OK);
    }

    @RequestMapping(value = "{id}", method = GET)
    public ResponseEntity<SamlServiceProvider> retrieveServiceProvider(@PathVariable String id) {
        SamlServiceProvider serviceProvider = serviceProviderProvisioning.retrieve(id, IdentityZoneHolder.get().getId());
        return new ResponseEntity<>(serviceProvider, OK);
    }

    @RequestMapping(value = "{id}", method = DELETE)
    public ResponseEntity<SamlServiceProvider> deleteServiceProvider(@PathVariable String id) {
        SamlServiceProvider serviceProvider = serviceProviderProvisioning.retrieve(id, IdentityZoneHolder.get().getId());
        serviceProviderProvisioning.delete(id, IdentityZoneHolder.get().getId());
        return new ResponseEntity<>(serviceProvider, OK);
    }

    @ExceptionHandler(MetadataProviderException.class)
    public ResponseEntity<String> handleMetadataProviderException(MetadataProviderException e) {
        if (e.getMessage().contains("Duplicate")) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.CONFLICT);
        } else {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @ExceptionHandler(JsonUtils.JsonUtilException.class)
    public ResponseEntity<String> handleMetadataProviderException() {
        return new ResponseEntity<>("Invalid provider configuration.", HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(EmptyResultDataAccessException.class)
    public ResponseEntity<String> handleProviderNotFoundException() {
        return new ResponseEntity<>("Provider not found.", HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(SamlSpAlreadyExistsException.class)
    public ResponseEntity<String> handleDuplicateServiceProvider() {
        return new ResponseEntity<>("SAML SP with the same entity id already exists.", HttpStatus.CONFLICT);
    }

}
