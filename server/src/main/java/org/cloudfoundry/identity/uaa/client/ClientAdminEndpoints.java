/*
 * *****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.client;

import com.jayway.jsonpath.JsonPathException;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsCreation;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtChangeRequest;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtActionResult;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtCredential;
import org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest;
import org.cloudfoundry.identity.uaa.provider.ClientAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.resources.ActionResult;
import org.cloudfoundry.identity.uaa.resources.AttributeNameMapper;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.resources.ResourceMonitor;
import org.cloudfoundry.identity.uaa.resources.SearchResults;
import org.cloudfoundry.identity.uaa.resources.SearchResultsFactory;
import org.cloudfoundry.identity.uaa.resources.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.util.UaaPagingUtils;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.InvalidClientSecretException;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.jmx.export.annotation.ManagedMetric;
import org.springframework.jmx.export.annotation.ManagedResource;
import org.springframework.jmx.support.MetricType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.BadClientCredentialsException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.jwk.JsonWebKey;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Controller for listing and manipulating OAuth2 clients.
 */
@Controller
@ManagedResource(
        objectName = "cloudfoundry.identity:name=ClientEndpoint",
        description = "UAA Oauth Clients API Metrics"
)
public class ClientAdminEndpoints implements ApplicationEventPublisherAware {

    private static final Logger logger = LoggerFactory.getLogger(ClientAdminEndpoints.class);
    private static final String SCIM_CLIENTS_SCHEMA_URI = "http://cloudfoundry.org/schema/scim/oauth-clients-1.0";

    private final SecurityContextAccessor securityContextAccessor;
    private final IdentityZoneManager identityZoneManager;
    private final ClientDetailsValidator clientDetailsValidator;
    private final AuthenticationManager authenticationManager;
    private final ResourceMonitor<ClientDetails> clientDetailsResourceMonitor;
    private final ApprovalStore approvalStore;
    private final MultitenantClientServices clientRegistrationService;
    private final QueryableResourceManager<ClientDetails> clientDetailsService;
    private final int clientMaxCount;

    private final AttributeNameMapper attributeNameMapper;
    private final RestrictUaaScopesClientValidator restrictedScopesValidator;
    private final Map<String, AtomicInteger> errorCounts;
    private final AtomicInteger clientUpdates;
    private final AtomicInteger clientDeletes;
    private final AtomicInteger clientSecretChanges;
    private final AtomicInteger clientJwtChanges;

    private ApplicationEventPublisher publisher;

    public ClientAdminEndpoints(final SecurityContextAccessor securityContextAccessor,
            final @Qualifier("identityZoneManager") IdentityZoneManager identityZoneManager,
            final @Qualifier("clientDetailsValidator") ClientDetailsValidator clientDetailsValidator,
            final @Qualifier("clientAuthenticationManager") AuthenticationManager authenticationManager,
            final @Qualifier("jdbcClientDetailsService") ResourceMonitor<ClientDetails> clientDetailsResourceMonitor,
            final @Qualifier("approvalStore") ApprovalStore approvalStore,
            final @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientRegistrationService,
            final @Qualifier("clientDetailsService") QueryableResourceManager<ClientDetails> clientDetailsService,
            final @Value("${clientMaxCount:500}") int clientMaxCount) {

        if (clientMaxCount <= 0) {
            throw new IllegalArgumentException(
                    "Invalid \"clientMaxCount\" value (got %d). Should be positive number.".formatted(clientMaxCount)
            );
        }

        this.securityContextAccessor = securityContextAccessor;
        this.identityZoneManager = identityZoneManager;
        this.clientDetailsValidator = clientDetailsValidator;
        this.authenticationManager = authenticationManager;
        this.clientDetailsResourceMonitor = clientDetailsResourceMonitor;
        this.approvalStore = approvalStore;
        this.clientRegistrationService = clientRegistrationService;
        this.clientDetailsService = clientDetailsService;
        this.clientMaxCount = clientMaxCount;
        this.attributeNameMapper = new SimpleAttributeNameMapper(Map.of(
                "client_id", "clientId",
                "resource_ids", "resourceIds",
                "authorized_grant_types", "authorizedGrantTypes",
                "redirect_uri", "registeredRedirectUri",
                "access_token_validity", "accessTokenValiditySeconds",
                "refresh_token_validity", "refreshTokenValiditySeconds",
                "autoapprove", "autoApproveScopes",
                "additionalinformation", "additionalInformation"));
        this.restrictedScopesValidator = new RestrictUaaScopesClientValidator(new UaaScopes());
        this.errorCounts = new ConcurrentHashMap<>();
        this.clientUpdates = new AtomicInteger();
        this.clientDeletes = new AtomicInteger();
        this.clientSecretChanges = new AtomicInteger();
        this.clientJwtChanges = new AtomicInteger();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "Client Registration Count")
    public int getTotalClients() {
        return clientDetailsResourceMonitor.getTotalCount();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "Client Update Count (Since Startup)")
    public int getClientUpdates() {
        return clientUpdates.get();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "Client Delete Count (Since Startup)")
    public int getClientDeletes() {
        return clientDeletes.get();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "Client Secret Change Count (Since Startup)")
    public int getClientSecretChanges() {
        return clientSecretChanges.get();
    }

    @ManagedMetric(metricType = MetricType.COUNTER, displayName = "Client Jwt Config Change Count (Since Startup)")
    public int getClientJwtChanges() {
        return clientJwtChanges.get();
    }

    @ManagedMetric(displayName = "Errors Since Startup")
    public Map<String, AtomicInteger> getErrorCounts() {
        return errorCounts;
    }

    @GetMapping("/oauth/clients/{client}")
    @ResponseBody
    public ClientDetails getClientDetails(@PathVariable String client) {
        try {
            return removeSecret(clientDetailsService.retrieve(client, identityZoneManager.getCurrentIdentityZoneId()));
        } catch (InvalidClientException _) {
            throw new NoSuchClientException("No such client: " + client);
        } catch (BadClientCredentialsException _) {
            // Defensive check, in case the clientDetailsService starts throwing
            // these instead
            throw new NoSuchClientException("No such client: " + client);
        }
    }

    @PostMapping({"/oauth/clients", "/oauth/clients/"})
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    @Transactional
    public ClientDetails createClientDetails(@RequestBody ClientDetailsCreation client) {
        final var createdClientDetails = createClientDetailsInternal(client);
        if (client.getSecondaryClientSecret() != null) {
            clientDetailsValidator.getClientSecretValidator().validate(client.getSecondaryClientSecret());
            clientRegistrationService.addClientSecret(createdClientDetails != null ? createdClientDetails.getClientId() : client.getClientId(),
                    client.getSecondaryClientSecret(), identityZoneManager.getCurrentIdentityZoneId());
        }
        return createdClientDetails;
    }

    private ClientDetails createClientDetailsInternal(UaaClientDetails client) {
        ClientDetails details = clientDetailsValidator.validate(client, Mode.CREATE);

        return removeSecret(clientDetailsService.create(details, identityZoneManager.getCurrentIdentityZoneId()));
    }

    @GetMapping("/oauth/clients/restricted")
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public List<String> getRestrictedClientScopes() {
        return restrictedScopesValidator.getUaaScopes().getUaaScopes();
    }


    @PostMapping({"/oauth/clients/restricted", "/oauth/clients/restricted/"})
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    public ClientDetails createRestrictedClientDetails(@RequestBody UaaClientDetails client) {
        restrictedScopesValidator.validate(client, Mode.CREATE);
        return createClientDetailsInternal(client);
    }

    @PostMapping({"/oauth/clients/tx", "/oauth/clients/tx/"})
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    @Transactional
    public ClientDetails[] createClientDetailsTx(@RequestBody UaaClientDetails[] clients) {
        if (clients == null || clients.length == 0) {
            throw new NoSuchClientException("Message body does not contain any clients.");
        }
        ClientDetails[] results = new ClientDetails[clients.length];
        for (int i = 0; i < clients.length; i++) {
            results[i] = clientDetailsValidator.validate(clients[i], Mode.CREATE);
        }
        return doInsertClientDetails(results);
    }

    protected ClientDetails[] doInsertClientDetails(ClientDetails[] details) {
        for (int i = 0; i < details.length; i++) {
            details[i] = clientDetailsService.create(details[i], identityZoneManager.getCurrentIdentityZoneId());
            details[i] = removeSecret(details[i]);
        }
        return details;
    }

    @PutMapping({"/oauth/clients/tx", "/oauth/clients/tx/"})
    @ResponseStatus(HttpStatus.OK)
    @Transactional
    @ResponseBody
    public ClientDetails[] updateClientDetailsTx(@RequestBody UaaClientDetails[] clients) {
        if (clients == null || clients.length == 0) {
            throw new InvalidClientDetailsException("No clients specified for update.");
        }
        ClientDetails[] details = new ClientDetails[clients.length];
        for (int i = 0; i < clients.length; i++) {
            ClientDetails client = clients[i];
            ClientDetails existing = getClientDetails(client.getClientId());
            if (existing == null) {
                throw new NoSuchClientException("Client " + client.getClientId() + " does not exist");
            } else {
                rejectRepeatedKidsInChangedClientJwtConfig(existing, client);
                details[i] = syncWithExisting(existing, client);
            }
            details[i] = validateClientUpdate(details[i], existing);
        }
        return doProcessUpdates(details);
    }

    protected ClientDetails[] doProcessUpdates(ClientDetails[] details) {
        ClientDetails[] result = new ClientDetails[details.length];
        for (int i = 0; i < result.length; i++) {
            clientRegistrationService.updateClientDetails(details[i], identityZoneManager.getCurrentIdentityZoneId());
            clientUpdates.incrementAndGet();
            result[i] = removeSecret(details[i]);
        }
        return result;

    }

    @PutMapping("/oauth/clients/restricted/{client}")
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public ClientDetails updateRestrictedClientDetails(@RequestBody UaaClientDetails client,
            @PathVariable("client") String clientId) throws Exception {
        restrictedScopesValidator.validate(client, Mode.MODIFY);
        return updateClientDetails(client, clientId);
    }

    @PutMapping("/oauth/clients/{client}")
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public ClientDetails updateClientDetails(@RequestBody UaaClientDetails client,
            @PathVariable("client") String clientId) {
        Assert.state(clientId.equals(client.getClientId()),
                "The client id (%s) does not match the URL (%s)".formatted(client.getClientId(), clientId));
        // A malformed value is rejected for every caller here: a failure in the merge below is only logged.
        if (StringUtils.hasText(client.getClientJwtConfig())) {
            ClientJwtConfiguration.readSuppliedValue(client.getClientJwtConfig());
        }
        ClientDetails details = client;
        ClientDetails existing = null;
        try {
            existing = getClientDetails(clientId);
            if (existing == null) {
                logger.warn("Couldn't fetch client config, null, for client_id: {}", clientId);
            } else {
                details = syncWithExisting(existing, client);
            }
        } catch (Exception e) {
            logger.warn("Couldn't fetch client config for client_id: {}", clientId, e);
            // The request is used as sent. The jwt configuration rules still apply, against the stored client as it is.
            if (existing == null) {
                existing = storedClientOrNull(clientId);
            }
            keepStoredClientJwtConfigurationForCallersWithoutPermission(details, existing);
        }
        rejectRepeatedKidsInChangedClientJwtConfig(existing, client);
        details = validateClientUpdate(details, existing);
        clientRegistrationService.updateClientDetails(details, identityZoneManager.getCurrentIdentityZoneId());
        clientUpdates.incrementAndGet();
        return removeSecret(clientDetailsService.retrieve(clientId, identityZoneManager.getCurrentIdentityZoneId()));
    }

    @DeleteMapping("/oauth/clients/{client}")
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public ClientDetails removeClientDetails(@PathVariable String client) {
        ClientDetails details = clientDetailsService.retrieve(client, identityZoneManager.getCurrentIdentityZoneId());
        doProcessDeletes(new ClientDetails[]{details});
        return removeSecret(details);
    }

    @PostMapping({"/oauth/clients/tx/delete", "/oauth/clients/tx/delete/"})
    @ResponseStatus(HttpStatus.OK)
    @Transactional
    @ResponseBody
    public ClientDetails[] removeClientDetailsTx(@RequestBody UaaClientDetails[] details) {
        ClientDetails[] result = new ClientDetails[details.length];
        for (int i = 0; i < result.length; i++) {
            result[i] = clientDetailsService.retrieve(details[i].getClientId(), identityZoneManager.getCurrentIdentityZoneId());
        }
        return doProcessDeletes(result);
    }

    @PostMapping({"/oauth/clients/tx/modify", "/oauth/clients/tx/modify/"})
    @ResponseStatus(HttpStatus.OK)
    @Transactional
    @ResponseBody
    public ClientDetailsModification[] modifyClientDetailsTx(@RequestBody ClientDetailsModification[] details) {
        ClientDetailsModification[] result = new ClientDetailsModification[details.length];
        for (int i = 0; i < result.length; i++) {
            if (ClientDetailsModification.ADD.equals(details[i].getAction())) {
                ClientDetails client = clientDetailsValidator.validate(details[i], Mode.CREATE);
                clientRegistrationService.addClientDetails(client, identityZoneManager.getCurrentIdentityZoneId());
                clientUpdates.incrementAndGet();
                result[i] = new ClientDetailsModification(clientDetailsService.retrieve(details[i].getClientId(), identityZoneManager.getCurrentIdentityZoneId()));
            } else if (ClientDetailsModification.DELETE.equals(details[i].getAction())) {
                result[i] = new ClientDetailsModification(clientDetailsService.retrieve(details[i].getClientId(), identityZoneManager.getCurrentIdentityZoneId()));
                doProcessDeletes(new ClientDetails[]{result[i]});
                result[i].setApprovalsDeleted(true);
            } else if (ClientDetailsModification.UPDATE.equals(details[i].getAction())) {
                result[i] = updateClientNotSecret(details[i]);
            } else if (ClientDetailsModification.UPDATE_SECRET.equals(details[i].getAction())) {
                boolean approvalsDeleted = updateClientSecret(details[i]);
                result[i] = updateClientNotSecret(details[i]);
                result[i].setApprovalsDeleted(approvalsDeleted);
            } else if (ClientDetailsModification.SECRET.equals(details[i].getAction())) {
                boolean approvalsDeleted = updateClientSecret(details[i]);
                result[i] = details[i];
                result[i].setApprovalsDeleted(approvalsDeleted);
            } else {
                throw new InvalidClientDetailsException("Invalid action.");
            }
            result[i].setAction(details[i].getAction());
            result[i].setClientSecret(null);
        }
        return result;
    }

    private ClientDetailsModification updateClientNotSecret(ClientDetailsModification c) {
        ClientDetails stored = clientDetailsService.retrieve(c.getClientId(), identityZoneManager.getCurrentIdentityZoneId());
        ClientDetailsModification result = new ClientDetailsModification(stored);
        rejectRepeatedKidsInChangedClientJwtConfig(stored, c);
        ClientDetails client = clientDetailsValidator.validate(c, Mode.MODIFY);
        clientRegistrationService.updateClientDetails(client, identityZoneManager.getCurrentIdentityZoneId());
        clientUpdates.incrementAndGet();
        return result;
    }

    private boolean updateClientSecret(ClientDetailsModification detail) {
        boolean deleteApprovals = !authenticateClient(detail.getClientId(), detail.getClientSecret());
        if (deleteApprovals) {
            clientDetailsValidator.getClientSecretValidator().validate(detail.getClientSecret());
            clientRegistrationService.updateClientSecret(detail.getClientId(), detail.getClientSecret(), identityZoneManager.getCurrentIdentityZoneId());
            deleteApprovals(detail.getClientId());
            detail.setApprovalsDeleted(true);
        }
        return deleteApprovals;
    }


    @PostMapping({"/oauth/clients/tx/secret", "/oauth/clients/tx/secret/"})
    @ResponseStatus(HttpStatus.OK)
    @Transactional
    @ResponseBody
    public ClientDetailsModification[] changeSecretTx(@RequestBody SecretChangeRequest[] change) {

        ClientDetailsModification[] clientDetails = new ClientDetailsModification[change.length];
        String clientId = null;
        try {
            for (int i = 0; i < change.length; i++) {
                clientId = change[i].getClientId();
                clientDetails[i] = new ClientDetailsModification(clientDetailsService.retrieve(clientId, identityZoneManager.getCurrentIdentityZoneId()));
                boolean oldPasswordOk = authenticateClient(clientId, change[i].getOldSecret());
                clientDetailsValidator.getClientSecretValidator().validate(change[i].getSecret());
                clientRegistrationService.updateClientSecret(clientId, change[i].getSecret(), identityZoneManager.getCurrentIdentityZoneId());
                if (!oldPasswordOk) {
                    deleteApprovals(clientId);
                    clientDetails[i].setApprovalsDeleted(true);
                }
                clientDetails[i] = removeSecret(clientDetails[i]);
            }
        } catch (InvalidClientException _) {
            throw new NoSuchClientException("No such client: " + clientId);
        }
        clientSecretChanges.getAndAdd(change.length);
        return clientDetails;
    }

    protected ClientDetails[] doProcessDeletes(ClientDetails[] details) {
        ClientDetailsModification[] result = new ClientDetailsModification[details.length];
        for (int i = 0; i < details.length; i++) {
            publish(new EntityDeletedEvent<>(details[i], SecurityContextHolder.getContext().getAuthentication(), identityZoneManager.getCurrentIdentityZoneId()));
            clientDeletes.incrementAndGet();
            result[i] = removeSecret(details[i]);
            result[i].setApprovalsDeleted(true);
        }
        return result;
    }

    protected void deleteApprovals(String clientId) {
        approvalStore.revokeApprovalsForClient(clientId, identityZoneManager.getCurrentIdentityZoneId());
    }

    @GetMapping({"/oauth/clients", "/oauth/clients/"})
    @ResponseBody
    public SearchResults<?> listClientDetails(
            @RequestParam(value = "attributes", required = false) String attributesCommaSeparated,
            @RequestParam(required = false, defaultValue = "client_id pr") String filter,
            @RequestParam(required = false, defaultValue = "client_id") String sortBy,
            @RequestParam(required = false, defaultValue = "ascending") String sortOrder,
            @RequestParam(required = false, defaultValue = "1") int startIndex,
            @RequestParam(required = false, defaultValue = "100") int count) {

        if (count > clientMaxCount) {
            count = clientMaxCount;
        }

        List<ClientDetails> result = new ArrayList<>();
        List<ClientDetails> clients;
        try {
            clients = clientDetailsService.query(filter, sortBy, "ascending".equalsIgnoreCase(sortOrder), identityZoneManager.getCurrentIdentityZoneId());
            if (count > clients.size()) {
                count = clients.size();
            }
        } catch (IllegalArgumentException _) {
            String msg = "Invalid filter expression: [" + HtmlUtils.htmlEscape(filter) + "]";
            if (StringUtils.hasText(sortBy)) {
                msg += " [" + HtmlUtils.htmlEscape(sortBy) + "]";
            }
            throw new UaaException(msg, HttpStatus.BAD_REQUEST.value());
        }
        for (ClientDetails client : UaaPagingUtils.subList(clients, startIndex, count)) {
            result.add(removeSecret(client));
        }

        if (!StringUtils.hasLength(attributesCommaSeparated)) {
            return new SearchResults<>(Collections.singletonList(SCIM_CLIENTS_SCHEMA_URI), result, startIndex, count,
                    clients.size());
        }

        String[] attributes = attributesCommaSeparated.split(",", -1);
        try {
            return SearchResultsFactory.buildSearchResultFrom(result, startIndex, count, clients.size(), attributes,
                    attributeNameMapper, Collections.singletonList(SCIM_CLIENTS_SCHEMA_URI));
        } catch (JsonPathException _) {
            throw new UaaException("Invalid attributes: [" + HtmlUtils.htmlEscape(attributesCommaSeparated) + "]",
                    HttpStatus.BAD_REQUEST.value());
        }
    }

    @PutMapping("/oauth/clients/{client_id}/secret")
    @ResponseBody
    public ActionResult changeSecret(@PathVariable String client_id, @RequestBody SecretChangeRequest change) {

        ClientDetails clientDetails;
        try {
            clientDetails = clientDetailsService.retrieve(client_id, identityZoneManager.getCurrentIdentityZoneId());
        } catch (InvalidClientException _) {
            throw new NoSuchClientException("No such client: " + client_id);
        }

        try {
            checkPasswordChangeIsAllowed(clientDetails, change.getOldSecret());
        } catch (IllegalStateException e) {
            throw new InvalidClientDetailsException(e.getMessage());
        }

        ActionResult result;
        switch (change.getChangeMode()) {
            case ADD :
                if (!validateCurrentClientSecretAdd(clientDetails.getClientSecret())) {
                    throw new InvalidClientDetailsException("client secret is either empty or client already has two secrets.");
                }
                clientDetailsValidator.getClientSecretValidator().validate(change.getSecret());
                clientRegistrationService.addClientSecret(client_id, change.getSecret(), identityZoneManager.getCurrentIdentityZoneId());
                result = new ActionResult("ok", "Secret is added");
                break;

            case DELETE :
                if (!validateCurrentClientSecretDelete(clientDetails.getClientSecret())) {
                    throw new InvalidClientDetailsException("client secret is either empty or client has only one secret.");
                }

                clientRegistrationService.deleteClientSecret(client_id, identityZoneManager.getCurrentIdentityZoneId());
                result = new ActionResult("ok", "Secret is deleted");
                break;

            default:
                clientDetailsValidator.getClientSecretValidator().validate(change.getSecret());
                clientRegistrationService.updateClientSecret(client_id, change.getSecret(), identityZoneManager.getCurrentIdentityZoneId());
                result = new ActionResult("ok", "secret updated");
        }
        clientSecretChanges.incrementAndGet();

        return result;
    }

    @PutMapping(value = "/oauth/clients/{client_id}/clientjwt")
    @ResponseBody
    public ActionResult changeClientJwt(@PathVariable String client_id, @RequestBody ClientJwtChangeRequest change) {

        UaaClientDetails uaaUaaClientDetails;
        try {
            uaaUaaClientDetails = (UaaClientDetails) clientDetailsService.retrieve(client_id, identityZoneManager.getCurrentIdentityZoneId());
        } catch (InvalidClientException _) {
            throw new NoSuchClientException("No such client: " + client_id);
        }

        try {
            checkPasswordChangeIsAllowed(uaaUaaClientDetails, "");
        } catch (IllegalStateException e) {
            throw new InvalidClientDetailsException(e.getMessage());
        }

        ClientJwtCredential federation = getValidatedFederation(change);
        ActionResult result;
        switch (change.getChangeMode()) {
            case ADD :
                if (change.getChangeValue() != null && federation == null) {
                    clientRegistrationService.addClientJwtConfig(client_id, change.getChangeValue(), identityZoneManager.getCurrentIdentityZoneId(), false);
                    result = new ActionResult("ok", "Client jwt configuration is added");
                } else {
                    if (federation != null) {
                        clientRegistrationService.addClientJwtCredential(client_id, federation,
                                identityZoneManager.getCurrentIdentityZoneId(), false);
                        result = new ActionResult("ok", "Federated client jwt configuration is added");
                    } else {
                        result = new ActionResult("ok", "No key added");
                    }
                }
                break;

            case DELETE :
                if (ClientJwtConfiguration.readValue(uaaUaaClientDetails) != null && change.getChangeValue() != null && federation == null) {
                    clientRegistrationService.deleteClientJwtConfig(client_id, change.getChangeValue(), identityZoneManager.getCurrentIdentityZoneId());
                    result = new ActionResult("ok", "Client jwt configuration is deleted");
                } else {
                    if (federation != null) {
                        clientRegistrationService.deleteClientJwtCredential(client_id, federation,
                                identityZoneManager.getCurrentIdentityZoneId());
                        result = new ActionResult("ok", "Federated client jwt configuration is deleted");
                    } else {
                        result = new ActionResult("ok", "No key deleted");
                    }
                }
                break;

            default:
                clientRegistrationService.addClientJwtConfig(client_id, change.getChangeValue(), identityZoneManager.getCurrentIdentityZoneId(), true);
                result = new ActionResult("ok", "Client jwt configuration updated");
        }
        clientJwtChanges.incrementAndGet();

        return withResultingClientJwtConfiguration(client_id, result);
    }

    /**
     * Adds the jwt configuration of the client as it is in effect after the change to the result: the configuration
     * that a read of the client returns and that client authentication uses, which includes federated credentials
     * kept as jwt_creds in the additional information. Concurrent changes of one client can replace each other; the
     * caller can see from this whether its change is part of the end state.
     */
    private ActionResult withResultingClientJwtConfiguration(String clientId, ActionResult result) {
        ClientJwtConfiguration stored = null;
        try {
            if (clientDetailsService.retrieve(clientId, identityZoneManager.getCurrentIdentityZoneId()) instanceof UaaClientDetails details) {
                stored = new UaaClient(
                        details.getClientId(),
                        details.getClientSecret(),
                        details.getAuthorities(),
                        new HashMap<>(Optional.ofNullable(details.getAdditionalInformation()).orElseGet(Collections::emptyMap)),
                        details.getClientJwtConfig()
                ).getClientJwtConfiguration();
            }
        } catch (InvalidClientException _) {
            // removed in the meantime: nothing is stored any more
        }
        List<String> kids = stored == null || stored.getJwkSet() == null ? List.of() :
                stored.getJwkSet().getKeys().stream().map(JsonWebKey::getKid).toList();
        String jwksUri = stored == null ? null : withoutUserInfo(stored.getJwksUri());
        List<ClientJwtCredential> credentials = stored == null || stored.getClientJwtCredentials() == null ?
                List.of() : stored.getClientJwtCredentials();
        return new ClientJwtActionResult(result.getStatus(), result.getMessage(), kids, jwksUri, credentials);
    }

    /**
     * A jwks_uri can carry user information (user:password@host), which can hold a password. The response of a jwt
     * change leaves it out and returns the rest of the address as stored.
     */
    private static String withoutUserInfo(String jwksUri) {
        if (jwksUri == null) {
            return null;
        }
        try {
            URI uri = new URI(jwksUri);
            if (uri.getRawUserInfo() == null) {
                return jwksUri;
            }
            return UriComponentsBuilder.fromUri(uri).userInfo(null).build(true).toUriString();
        } catch (URISyntaxException | IllegalArgumentException _) {
            // stored values are validated as a URI; a value that is not one is left out
            return null;
        }
    }

    private ClientJwtCredential getValidatedFederation(ClientJwtChangeRequest change) {
        if (!change.isFederated()) {
            return null;
        }
        try {
            return change.getFederation();
        } catch (IllegalArgumentException e) {
            throw new InvalidClientDetailsException(e.getMessage(), e);
        }
    }

    private boolean validateCurrentClientSecretAdd(String clientSecret) {
        return clientSecret == null || clientSecret.split(" ").length == 1;
    }

    private boolean validateCurrentClientSecretDelete(String clientSecret) {
        return clientSecret != null && clientSecret.split(" ").length == 2;
    }

    @ExceptionHandler(InvalidClientSecretException.class)
    public ResponseEntity<InvalidClientSecretException> handleInvalidClientSecret(InvalidClientSecretException e) {
        incrementErrorCounts(e);
        return new ResponseEntity<>(e, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(InvalidClientDetailsException.class)
    public ResponseEntity<InvalidClientDetailsException> handleInvalidClientDetails(InvalidClientDetailsException e) {
        incrementErrorCounts(e);
        return new ResponseEntity<>(e, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(NoSuchClientException.class)
    public ResponseEntity<Void> handleNoSuchClient(NoSuchClientException e) {
        incrementErrorCounts(e);
        return new ResponseEntity<>(HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(ClientAlreadyExistsException.class)
    public ResponseEntity<InvalidClientDetailsException> handleClientAlreadyExists(ClientAlreadyExistsException e) {
        incrementErrorCounts(e);
        return new ResponseEntity<>(new InvalidClientDetailsException(e.getMessage()),
                HttpStatus.CONFLICT);
    }

    @ExceptionHandler(UaaException.class)
    public ResponseEntity<UaaException> handleUaaException(UaaException e) {
        incrementErrorCounts(e);
        return new ResponseEntity<>(e, HttpStatus.valueOf(e.getHttpStatus()));
    }

    private void incrementErrorCounts(Exception e) {
        String series = UaaStringUtils.getErrorName(e);
        errorCounts.computeIfAbsent(series, _ -> new AtomicInteger()).incrementAndGet();
    }


    private void checkPasswordChangeIsAllowed(ClientDetails clientDetails, String oldSecret) {
        String clientId = clientDetails.getClientId();

        // Call is by client
        String currentClientId = securityContextAccessor.getClientId();

        if (!securityContextAccessor.isAdmin() && !securityContextAccessor.getScopes().contains("clients.admin")) {
            if (!clientId.equals(currentClientId)) {
                logger.warn("Client with id {} attempting to change password for client {}", currentClientId, clientId);
                throw new IllegalStateException("Bad request. Not permitted to change another client's secret");
            }

            // Client is changing their own secret, old password is required
            if (!authenticateClient(clientId, oldSecret)) {
                throw new IllegalStateException("Previous secret is required and must be valid");
            }
        }

    }

    private boolean authenticateClient(String clientId, String clientSecret) {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(clientId, clientSecret);
        try {
            HttpServletRequest curRequest =
                    ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            if (curRequest != null) {
                authentication.setDetails(new UaaAuthenticationDetails(curRequest, clientId));
            }
        } catch (IllegalStateException _) {
            //ignore - means no thread bound request found
        }
        try {
            Authentication auth = authenticationManager.authenticate(authentication);
            return auth.isAuthenticated();
        } catch (AuthenticationException _) {
            return false;
        } catch (Exception e) {
            logger.debug("Unable to authenticate/validate {}", clientId, e);
            return false;
        }
    }

    private ClientDetailsModification removeSecret(ClientDetails client) {
        if (client == null) {
            return null;
        }
        ClientDetailsModification details = new ClientDetailsModification(client);
        details.setClientSecret(null);
        return details;
    }

    private ClientDetails validateClientUpdate(ClientDetails details, ClientDetails existing) {
        if (details instanceof UaaClientDetails uaa && !mayChangeClientJwtConfiguration(uaa.getClientId())) {
            // The supplied configuration was checked before merging. The retained stored value is not input:
            // validate the other fields without reparsing it, then restore it verbatim, even if it is unreadable.
            UaaClientDetails toValidate = new UaaClientDetails(uaa);
            if (uaa.getAutoApproveScopes() != null) {
                toValidate.setAutoApproveScopes(uaa.getAutoApproveScopes());
            }
            toValidate.setClientJwtConfig(null);
            ClientDetails validated = clientDetailsValidator.validate(toValidate, Mode.MODIFY);
            keepStoredClientJwtConfigurationForCallersWithoutPermission(validated, existing);
            return validated;
        }
        return clientDetailsValidator.validate(details, Mode.MODIFY);
    }

    private ClientDetails syncWithExisting(ClientDetails existing, ClientDetails input) {
        UaaClientDetails details = new UaaClientDetails(input);
        if (input instanceof UaaClientDetails baseInput) {
            if (baseInput.getAutoApproveScopes() != null) {
                details.setAutoApproveScopes(baseInput.getAutoApproveScopes());
            } else {
                details.setAutoApproveScopes(new HashSet<>());
                if (existing instanceof UaaClientDetails existingDetails && existingDetails.getAutoApproveScopes() != null) {
                    for (String scope : existingDetails.getAutoApproveScopes()) {
                            details.getAutoApproveScopes().add(scope);
                    }
                }
            }

        }

        if (details.getAccessTokenValiditySeconds() == null) {
            details.setAccessTokenValiditySeconds(existing.getAccessTokenValiditySeconds());
        }
        if (details.getRefreshTokenValiditySeconds() == null) {
            details.setRefreshTokenValiditySeconds(existing.getRefreshTokenValiditySeconds());
        }
        if (details.getAuthorities() == null || details.getAuthorities().isEmpty()) {
            details.setAuthorities(existing.getAuthorities());
        }
        if (details.getAuthorizedGrantTypes() == null || details.getAuthorizedGrantTypes().isEmpty()) {
            details.setAuthorizedGrantTypes(existing.getAuthorizedGrantTypes());
        }
        if (details.getRegisteredRedirectUri() == null || details.getRegisteredRedirectUri().isEmpty()) {
            details.setRegisteredRedirectUri(existing.getRegisteredRedirectUri());
        }
        if (details.getResourceIds() == null || details.getResourceIds().isEmpty()) {
            details.setResourceIds(existing.getResourceIds());
        }
        if (details.getScope() == null || details.getScope().isEmpty()) {
            details.setScope(existing.getScope());
        }

        Map<String, Object> additionalInformation = new HashMap<>(existing.getAdditionalInformation());
        additionalInformation.putAll(input.getAdditionalInformation());
        for (String key : Set.copyOf(additionalInformation.keySet())) {
            if (additionalInformation.get(key) == null) {
                additionalInformation.remove(key);
            }
        }
        if (Boolean.FALSE.equals(additionalInformation.get(ClientConstants.ALLOW_PUBLIC))) {
            additionalInformation.remove(ClientConstants.ALLOW_PUBLIC);
        }

        if (existing instanceof UaaClientDetails existingUaa && input instanceof UaaClientDetails inputUaa && details instanceof UaaClientDetails detailsUaa) {
            // Reject malformed input before it is parsed below, where the batch update would
            // otherwise answer with a server error before validation runs.
            if (StringUtils.hasText(inputUaa.getClientJwtConfig())) {
                ClientJwtConfiguration.readSuppliedValue(inputUaa.getClientJwtConfig());
            }
            // Changing the keys of a client has its own endpoint (PUT /oauth/clients/{id}/clientjwt, clients.trust).
            // Callers that may not use it keep the raw stored configuration without parsing or normalizing it.
            if (mayChangeClientJwtConfiguration(existingUaa.getClientId())) {
                UaaClient existingAsClient = new UaaClient(
                        existingUaa.getClientId(),
                        existingUaa.getClientSecret(),
                        existingUaa.getAuthorities(),
                        new HashMap<>(Optional.ofNullable(existingUaa.getAdditionalInformation()).orElseGet(Collections::emptyMap)),
                        existingUaa.getClientJwtConfig()
                );
                UaaClient inputAsClient = new UaaClient(
                        inputUaa.getClientId(),
                        inputUaa.getClientSecret(),
                        inputUaa.getAuthorities(),
                        new HashMap<>(Optional.ofNullable(inputUaa.getAdditionalInformation()).orElseGet(Collections::emptyMap)),
                        inputUaa.getClientJwtConfig()
                );
                ClientJwtConfiguration existingJwt = existingAsClient.getClientJwtConfiguration();
                ClientJwtConfiguration inputJwt = inputAsClient.getClientJwtConfiguration();
                inputJwt = ensureJwtCredsFromAdditionalInfoMap(additionalInformation, inputJwt);
                ClientJwtConfiguration mergedJwtConfig = ClientJwtConfiguration.merge(existingJwt, inputJwt, false);
                if (mergedJwtConfig != null && mergedJwtConfig.hasConfiguration()) {
                    mergedJwtConfig.writeValue(detailsUaa);
                }
            } else {
                detailsUaa.setClientJwtConfig(existingUaa.getClientJwtConfig());
            }
        }

        additionalInformation.remove(ClientJwtConfiguration.JWT_CREDS);
        additionalInformation.remove("client_jwt_config");
        details.setAdditionalInformation(additionalInformation);

        return details;
    }

    /**
     * A key set that repeats a kid is rejected like on create. A stored value can repeat a kid (it was stored before
     * the rule), so a value that is sent back unchanged is accepted. Callers that may not change the configuration
     * are not checked: their value is not applied.
     */
    private void rejectRepeatedKidsInChangedClientJwtConfig(ClientDetails existing, ClientDetails input) {
        if (existing instanceof UaaClientDetails existingUaa
                && input instanceof UaaClientDetails inputUaa
                && StringUtils.hasText(inputUaa.getClientJwtConfig())
                && !inputUaa.getClientJwtConfig().equals(existingUaa.getClientJwtConfig())
                && mayChangeClientJwtConfiguration(inputUaa.getClientId())) {
            ClientJwtConfiguration.rejectRepeatedKids(inputUaa.getClientJwtConfig());
        }
    }

    /**
     * When merging fails, the update continues with the request as sent. Callers that may not change the jwt
     * configuration must not get theirs stored that way: the stored value stays.
     */
    private void keepStoredClientJwtConfigurationForCallersWithoutPermission(ClientDetails details, ClientDetails existing) {
        if (details instanceof UaaClientDetails detailsUaa && !mayChangeClientJwtConfiguration(detailsUaa.getClientId())) {
            detailsUaa.setClientJwtConfig(existing instanceof UaaClientDetails existingUaa ? existingUaa.getClientJwtConfig() : null);
            Map<String, Object> additionalInformation = new HashMap<>(Optional.ofNullable(detailsUaa.getAdditionalInformation()).orElseGet(Collections::emptyMap));
            additionalInformation.remove(ClientJwtConfiguration.JWT_CREDS);
            additionalInformation.remove("client_jwt_config");
            detailsUaa.setAdditionalInformation(additionalInformation);
        }
    }

    // The stored client without reading its jwt configuration, or null when it cannot be loaded (the update then
    // answers for the missing client).
    private ClientDetails storedClientOrNull(String clientId) {
        try {
            return clientDetailsService.retrieve(clientId, identityZoneManager.getCurrentIdentityZoneId());
        } catch (RuntimeException e) {
            logger.debug("Couldn't load client_id: {}", clientId, e);
            return null;
        }
    }

    // As for PUT /oauth/clients/{id}/clientjwt, clients.trust covers only the caller's own client.
    private boolean mayChangeClientJwtConfiguration(String clientId) {
        Collection<String> scopes = securityContextAccessor.getScopes();
        return securityContextAccessor.isAdmin()
                || scopes.contains("clients.admin")
                || (scopes.contains("clients.trust") && clientId != null && clientId.equals(securityContextAccessor.getClientId()));
    }

    private ClientJwtConfiguration ensureJwtCredsFromAdditionalInfoMap(Map<String, Object> addl, ClientJwtConfiguration inputJwt) {
        if (addl == null) {
            return inputJwt;
        }
        Object v = addl.get(ClientJwtConfiguration.JWT_CREDS);
        if (v == null) {
            return inputJwt;
        }
        try {
            ClientJwtConfiguration extra = ClientJwtConfiguration.fromJwtCredsValue(v);
            if (extra == null) {
                return inputJwt;
            }
            return ClientJwtConfiguration.merge(inputJwt, extra, false);
        } catch (Exception e) {
            logger.warn("Failed to read jwt_creds from client update request", e);
            return inputJwt;
        }
    }

    public void publish(ApplicationEvent event) {
        if (publisher != null) {
            publisher.publishEvent(event);
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        publisher = applicationEventPublisher;
    }
}
