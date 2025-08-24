package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.cloudfoundry.identity.uaa.web.ExceptionReportHttpMessageConverter;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.View;

import jakarta.servlet.http.HttpServletRequest;
import java.util.List;

@Controller
public class ClientMetadataAdminEndpoints {
    private static Logger logger = LoggerFactory.getLogger(ClientMetadataAdminEndpoints.class);
    private final ClientMetadataProvisioning clientMetadataProvisioning;
    private final HttpMessageConverter<?>[] messageConverters;

    public ClientMetadataAdminEndpoints(final @Qualifier("jdbcClientMetadataProvisioning") ClientMetadataProvisioning clientMetadataProvisioning) {
        this.clientMetadataProvisioning = clientMetadataProvisioning;
        this.messageConverters = new HttpMessageConverter[]{
                new ExceptionReportHttpMessageConverter()
        };
    }

    @GetMapping("/oauth/clients/{client}/meta")
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public ClientMetadata retrieveClientMetadata(@PathVariable("client") String clientId) {
        try {
            return clientMetadataProvisioning.retrieve(clientId, IdentityZoneHolder.get().getId());
        } catch (EmptyResultDataAccessException erdae) {
            throw new ClientMetadataException("No client metadata found for " + clientId, HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/oauth/clients/meta")
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public List<ClientMetadata> retrieveAllClientMetadata() {
        return clientMetadataProvisioning.retrieveAll(IdentityZoneHolder.get().getId());
    }

    @PutMapping("/oauth/clients/{client}/meta")
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public ClientMetadata updateClientMetadata(@RequestBody ClientMetadata clientMetadata,
            @PathVariable("client") String clientId) {

        if (StringUtils.hasText(clientMetadata.getClientId())) {
            if (!clientId.equals(clientMetadata.getClientId())) {
                throw new ClientMetadataException("Client ID in body {" + clientMetadata.getClientId() + "} does not match URL path {" + clientId + "}",
                        HttpStatus.BAD_REQUEST);
            }
        } else {
            clientMetadata.setClientId(clientId);
        }
        try {
            return clientMetadataProvisioning.update(clientMetadata, IdentityZoneHolder.get().getId());
        } catch (EmptyResultDataAccessException e) {
            throw new ClientMetadataException("No client with ID " + clientMetadata.getClientId(),
                    HttpStatus.NOT_FOUND);
        }
    }

    @ExceptionHandler
    public View handleException(ClientMetadataException cme, HttpServletRequest request) {
        logger.error("Unhandled exception in client metadata admin endpoints.", cme);

        boolean trace = request.getParameter("trace") != null && !"false".equals(request.getParameter("trace"));
        return new ConvertingExceptionView(new ResponseEntity<>(new ExceptionReport(cme, trace, cme.getExtraInfo()),
                cme.getStatus()), messageConverters);
    }
}
