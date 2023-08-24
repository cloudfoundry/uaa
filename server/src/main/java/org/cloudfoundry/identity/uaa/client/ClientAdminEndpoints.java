/*******************************************************************************
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

import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsCreation;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.oauth.client.ClientJwtChangeRequest;
import org.cloudfoundry.identity.uaa.oauth.client.SecretChangeRequest;
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
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.InvalidClientSecretException;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.expression.spel.SpelParseException;
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
import org.springframework.security.oauth2.common.exceptions.BadClientCredentialsException;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static java.lang.String.format;

/**
 * Controller for listing and manipulating OAuth2 clients.
 */
@Controller
@ManagedResource(
    objectName="cloudfoundry.identity:name=ClientEndpoint",
    description = "UAA Oauth Clients API Metrics"
)
public class ClientAdminEndpoints implements ApplicationEventPublisherAware {

    private static final Logger logger = LoggerFactory.getLogger(ClientAdminEndpoints.class);
    private static final String SCIM_CLIENTS_SCHEMA_URI = "http://cloudfoundry.org/schema/scim/oauth-clients-1.0";

    private final SecurityContextAccessor securityContextAccessor;
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

    private ApplicationEventPublisher publisher;

    public ClientAdminEndpoints(final SecurityContextAccessor securityContextAccessor,
                                final @Qualifier("clientDetailsValidator") ClientDetailsValidator clientDetailsValidator,
                                final @Qualifier("clientAuthenticationManager") AuthenticationManager authenticationManager,
                                final @Qualifier("jdbcClientDetailsService") ResourceMonitor<ClientDetails> clientDetailsResourceMonitor,
                                final @Qualifier("approvalStore") ApprovalStore approvalStore,
                                final @Qualifier("jdbcClientDetailsService") MultitenantClientServices clientRegistrationService,
                                final @Qualifier("clientDetailsService") QueryableResourceManager<ClientDetails> clientDetailsService,
                                final @Value("${clientMaxCount:500}") int clientMaxCount) {

        if (clientMaxCount <= 0) {
            throw new IllegalArgumentException(
                    format("Invalid \"clientMaxCount\" value (got %d). Should be positive number.", clientMaxCount)
            );
        }

        this.securityContextAccessor = securityContextAccessor;
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

    @ManagedMetric(displayName = "Errors Since Startup")
    public Map<String, AtomicInteger> getErrorCounts() {
        return errorCounts;
    }

    @RequestMapping(value = "/oauth/clients/{client}", method = RequestMethod.GET)
    @ResponseBody
    public ClientDetails getClientDetails(@PathVariable String client) {
        try {
            return removeSecret(clientDetailsService.retrieve(client, IdentityZoneHolder.get().getId()));
        } catch (InvalidClientException e) {
            throw new NoSuchClientException("No such client: " + client);
        } catch (BadClientCredentialsException e) {
            // Defensive check, in case the clientDetailsService starts throwing
            // these instead
            throw new NoSuchClientException("No such client: " + client);
        }
    }

    @RequestMapping(value = "/oauth/clients", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    @Transactional
    public ClientDetails createClientDetails(@RequestBody ClientDetailsCreation client) {
        final var createdClientDetails = createClientDetailsInternal(client);
        if (client.getSecondaryClientSecret() != null) {
            clientDetailsValidator.getClientSecretValidator().validate(client.getSecondaryClientSecret());
            clientRegistrationService.addClientSecret(createdClientDetails != null ? createdClientDetails.getClientId() : client.getClientId(),
                    client.getSecondaryClientSecret(), IdentityZoneHolder.get().getId());
        }
        return createdClientDetails;
    }

    private ClientDetails createClientDetailsInternal(BaseClientDetails client) {
        ClientDetails details = clientDetailsValidator.validate(client, Mode.CREATE);

        return removeSecret(clientDetailsService.create(details, IdentityZoneHolder.get().getId()));
    }

    @RequestMapping(value = "/oauth/clients/restricted", method = RequestMethod.GET)
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public List<String> getRestrictedClientScopes() {
        return restrictedScopesValidator.getUaaScopes().getUaaScopes();
    }


    @RequestMapping(value = "/oauth/clients/restricted", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    public ClientDetails createRestrictedClientDetails(@RequestBody BaseClientDetails client) {
        restrictedScopesValidator.validate(client, Mode.CREATE);
        return createClientDetailsInternal(client);
    }

    @RequestMapping(value = "/oauth/clients/tx", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.CREATED)
    @ResponseBody
    @Transactional
    public ClientDetails[] createClientDetailsTx(@RequestBody BaseClientDetails[] clients) {
        if (clients==null || clients.length==0) {
            throw new NoSuchClientException("Message body does not contain any clients.");
        }
        ClientDetails[] results = new ClientDetails[clients.length];
        for (int i=0; i<clients.length; i++) {
            results[i] = clientDetailsValidator.validate(clients[i], Mode.CREATE);
        }
        return doInsertClientDetails(results);
    }

    protected ClientDetails[] doInsertClientDetails(ClientDetails[] details) {
        for (int i=0; i<details.length; i++) {
            details[i] = clientDetailsService.create(details[i], IdentityZoneHolder.get().getId());
            details[i] = removeSecret(details[i]);
        }
        return details;
    }

    @RequestMapping(value = "/oauth/clients/tx", method = RequestMethod.PUT)
    @ResponseStatus(HttpStatus.OK)
    @Transactional
    @ResponseBody
    public ClientDetails[] updateClientDetailsTx(@RequestBody BaseClientDetails[] clients) {
        if (clients==null || clients.length==0) {
            throw new InvalidClientDetailsException("No clients specified for update.");
        }
        ClientDetails[] details = new ClientDetails[clients.length];
        for (int i=0; i<clients.length; i++) {
            ClientDetails client = clients[i];
            ClientDetails existing = getClientDetails(client.getClientId());
            if (existing==null) {
                throw new NoSuchClientException("Client "+client.getClientId()+" does not exist");
            } else {
                details[i] = syncWithExisting(existing, client);
            }
            details[i] = clientDetailsValidator.validate(details[i], Mode.MODIFY);
        }
        return doProcessUpdates(details);
    }

    protected ClientDetails[] doProcessUpdates(ClientDetails[] details) {
        ClientDetails[] result = new ClientDetails[details.length];
        for (int i=0; i<result.length; i++) {
            clientRegistrationService.updateClientDetails(details[i], IdentityZoneHolder.get().getId());
            clientUpdates.incrementAndGet();
            result[i] = removeSecret(details[i]);
        }
        return result;

    }

    @RequestMapping(value = "/oauth/clients/restricted/{client}", method = RequestMethod.PUT)
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public ClientDetails updateRestrictedClientDetails(@RequestBody BaseClientDetails client,
                                                       @PathVariable("client") String clientId) throws Exception {
        restrictedScopesValidator.validate(client, Mode.MODIFY);
        return updateClientDetails(client, clientId);
    }

    @RequestMapping(value = "/oauth/clients/{client}", method = RequestMethod.PUT)
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public ClientDetails updateClientDetails(@RequestBody BaseClientDetails client,
                    @PathVariable("client") String clientId) {
        Assert.state(clientId.equals(client.getClientId()),
                        format("The client id (%s) does not match the URL (%s)", client.getClientId(), clientId));
        ClientDetails details = client;
        try {
            ClientDetails existing = getClientDetails(clientId);
            if (existing==null) {
                logger.warn("Couldn't fetch client config, null, for client_id: " + clientId);
            } else {
                details = syncWithExisting(existing, client);
            }
        } catch (Exception e) {
            logger.warn("Couldn't fetch client config for client_id: " + clientId, e);
        }
        details = clientDetailsValidator.validate(details, Mode.MODIFY);
        clientRegistrationService.updateClientDetails(details, IdentityZoneHolder.get().getId());
        clientUpdates.incrementAndGet();
        return removeSecret(clientDetailsService.retrieve(clientId, IdentityZoneHolder.get().getId()));
    }

    @RequestMapping(value = "/oauth/clients/{client}", method = RequestMethod.DELETE)
    @ResponseStatus(HttpStatus.OK)
    @ResponseBody
    public ClientDetails removeClientDetails(@PathVariable String client) {
        ClientDetails details = clientDetailsService.retrieve(client, IdentityZoneHolder.get().getId());
        doProcessDeletes(new ClientDetails[]{details});
        return removeSecret(details);
    }

    @RequestMapping(value = "/oauth/clients/tx/delete", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.OK)
    @Transactional
    @ResponseBody
    public ClientDetails[] removeClientDetailsTx(@RequestBody BaseClientDetails[] details) {
        ClientDetails[] result = new ClientDetails[details.length];
        for (int i=0; i<result.length; i++) {
            result[i] = clientDetailsService.retrieve(details[i].getClientId(), IdentityZoneHolder.get().getId());
        }
        return doProcessDeletes(result);
    }

    @RequestMapping(value = "/oauth/clients/tx/modify", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.OK)
    @Transactional
    @ResponseBody
    public ClientDetailsModification[] modifyClientDetailsTx(@RequestBody ClientDetailsModification[] details) {
        ClientDetailsModification[] result = new ClientDetailsModification[details.length];
        for (int i=0; i<result.length; i++) {
            if (ClientDetailsModification.ADD.equals(details[i].getAction())) {
                ClientDetails client = clientDetailsValidator.validate(details[i], Mode.CREATE);
                clientRegistrationService.addClientDetails(client, IdentityZoneHolder.get().getId());
                clientUpdates.incrementAndGet();
                result[i] = new ClientDetailsModification(clientDetailsService.retrieve(details[i].getClientId(), IdentityZoneHolder.get().getId()));
            } else if (ClientDetailsModification.DELETE.equals(details[i].getAction())) {
                result[i] = new ClientDetailsModification(clientDetailsService.retrieve(details[i].getClientId(), IdentityZoneHolder.get().getId()));
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
        ClientDetailsModification result = new ClientDetailsModification(clientDetailsService.retrieve(c.getClientId(), IdentityZoneHolder.get().getId()));
        ClientDetails client = clientDetailsValidator.validate(c, Mode.MODIFY);
        clientRegistrationService.updateClientDetails(client, IdentityZoneHolder.get().getId());
        clientUpdates.incrementAndGet();
        return result;
    }

    private boolean updateClientSecret(ClientDetailsModification detail) {
        boolean deleteApprovals = !(authenticateClient(detail.getClientId(), detail.getClientSecret()));
        if (deleteApprovals) {
            clientRegistrationService.updateClientSecret(detail.getClientId(), detail.getClientSecret(), IdentityZoneHolder.get().getId());
            deleteApprovals(detail.getClientId());
            detail.setApprovalsDeleted(true);
        }
        return deleteApprovals;
    }


    @RequestMapping(value = "/oauth/clients/tx/secret", method = RequestMethod.POST)
    @ResponseStatus(HttpStatus.OK)
    @Transactional
    @ResponseBody
    public ClientDetailsModification[] changeSecretTx(@RequestBody SecretChangeRequest[] change) {

        ClientDetailsModification[] clientDetails = new ClientDetailsModification[change.length];
        String clientId=null;
        try {
            for (int i=0; i<change.length; i++) {
                clientId = change[i].getClientId();
                clientDetails[i] = new ClientDetailsModification(clientDetailsService.retrieve(clientId, IdentityZoneHolder.get().getId()));
                boolean oldPasswordOk = authenticateClient(clientId, change[i].getOldSecret());
                clientDetailsValidator.getClientSecretValidator().validate(change[i].getSecret());
                clientRegistrationService.updateClientSecret(clientId, change[i].getSecret(), IdentityZoneHolder.get().getId());
                if (!oldPasswordOk) {
                    deleteApprovals(clientId);
                    clientDetails[i].setApprovalsDeleted(true);
                }
                clientDetails[i] = removeSecret(clientDetails[i]);
            }
        } catch (InvalidClientException e) {
            throw new NoSuchClientException("No such client: " + clientId);
        }
        clientSecretChanges.getAndAdd(change.length);
        return clientDetails;
    }

    protected ClientDetails[] doProcessDeletes(ClientDetails[] details) {
        ClientDetailsModification[] result = new ClientDetailsModification[details.length];
        for (int i=0; i<details.length; i++) {
            publish(new EntityDeletedEvent<>(details[i], SecurityContextHolder.getContext().getAuthentication(), IdentityZoneHolder.getCurrentZoneId()));
            clientDeletes.incrementAndGet();
            result[i] = removeSecret(details[i]);
            result[i].setApprovalsDeleted(true);
        }
        return result;
    }

    protected void deleteApprovals(String clientId) {
        approvalStore.revokeApprovalsForClient(clientId, IdentityZoneHolder.get().getId());
    }

    @RequestMapping(value = "/oauth/clients", method = RequestMethod.GET)
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

        List<ClientDetails> result = new ArrayList<ClientDetails>();
        List<ClientDetails> clients;
        try {
            clients = clientDetailsService.query(filter, sortBy, "ascending".equalsIgnoreCase(sortOrder), IdentityZoneHolder.get().getId());
            if (count > clients.size()) {
                count = clients.size();
            }
        } catch (IllegalArgumentException e) {
            String msg = "Invalid filter expression: [" + filter + "]";
            if (StringUtils.hasText(sortBy)) {
                msg += " [" +sortBy+"]";
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

        String[] attributes = attributesCommaSeparated.split(",");
        try {
            return SearchResultsFactory.buildSearchResultFrom(result, startIndex, count, clients.size(), attributes,
                            attributeNameMapper, Collections.singletonList(SCIM_CLIENTS_SCHEMA_URI));
        } catch (SpelParseException e) {
            throw new UaaException("Invalid attributes: [" + attributesCommaSeparated + "]",
                            HttpStatus.BAD_REQUEST.value());
        } catch (SpelEvaluationException e) {
            throw new UaaException("Invalid attributes: [" + attributesCommaSeparated + "]",
                            HttpStatus.BAD_REQUEST.value());
        }
    }

    @RequestMapping(value = "/oauth/clients/{client_id}/secret", method = RequestMethod.PUT)
    @ResponseBody
    public ActionResult changeSecret(@PathVariable String client_id, @RequestBody SecretChangeRequest change) {

        ClientDetails clientDetails;
        try {
            clientDetails = clientDetailsService.retrieve(client_id, IdentityZoneHolder.get().getId());
        } catch (InvalidClientException e) {
            throw new NoSuchClientException("No such client: " + client_id);
        }

        try {
            checkPasswordChangeIsAllowed(clientDetails, change.getOldSecret());
        } catch (IllegalStateException e) {
            throw new InvalidClientDetailsException(e.getMessage());
        }

        ActionResult result;
        switch (change.getChangeMode()){
            case ADD :
                if(!validateCurrentClientSecretAdd(clientDetails.getClientSecret())) {
                    throw new InvalidClientDetailsException("client secret is either empty or client already has two secrets.");
                }
                clientDetailsValidator.getClientSecretValidator().validate(change.getSecret());
                clientRegistrationService.addClientSecret(client_id, change.getSecret(), IdentityZoneHolder.get().getId());
                result = new ActionResult("ok", "Secret is added");
                break;

            case DELETE :
                if(!validateCurrentClientSecretDelete(clientDetails.getClientSecret())) {
                    throw new InvalidClientDetailsException("client secret is either empty or client has only one secret.");
                }

                clientRegistrationService.deleteClientSecret(client_id, IdentityZoneHolder.get().getId());
                result = new ActionResult("ok", "Secret is deleted");
                break;

            default:
                clientDetailsValidator.getClientSecretValidator().validate(change.getSecret());
                clientRegistrationService.updateClientSecret(client_id, change.getSecret(), IdentityZoneHolder.get().getId());
                result = new ActionResult("ok", "secret updated");
        }
        clientSecretChanges.incrementAndGet();

        return result;
    }

    @RequestMapping(value = "/oauth/clients/{client_id}/clientjwt", method = RequestMethod.PUT)
    @ResponseBody
    public ActionResult changeClientJwt(@PathVariable String client_id, @RequestBody ClientJwtChangeRequest change) {

        UaaClientDetails uaaClientDetails;
        try {
            uaaClientDetails = (UaaClientDetails) clientDetailsService.retrieve(client_id, IdentityZoneHolder.get().getId());
        } catch (InvalidClientException e) {
            throw new NoSuchClientException("No such client: " + client_id);
        }

        try {
            checkPasswordChangeIsAllowed(uaaClientDetails, "");
        } catch (IllegalStateException e) {
            throw new InvalidClientDetailsException(e.getMessage());
        }

        ClientJwtConfiguration clientKeyConfig = ClientJwtConfiguration.readValue(uaaClientDetails);

        ActionResult result;
        switch (change.getChangeMode()){
            case ADD :
                if (change.getKey() != null) {
                    clientRegistrationService.addClientJwtConfig(client_id, change.getKey(), IdentityZoneHolder.get().getId(), false);
                    result = new ActionResult("ok", "Client jwt configuration is added");
                } else {
                    result = new ActionResult("ok", "No key added");
                }
                break;

            case DELETE :
                String deleteString = change.getKeyId() == null ? change.getKey() : change.getKeyId();
                if (clientKeyConfig != null && deleteString != null) {
                    clientRegistrationService.deleteClientJwtConfig(client_id, deleteString, IdentityZoneHolder.get().getId());
                }
                result = new ActionResult("ok", "Client jwt configuration is deleted");
                break;

            default:
                clientRegistrationService.addClientJwtConfig(client_id, change.getKey(), IdentityZoneHolder.get().getId(), true);
                result = new ActionResult("ok", "Client jwt configuration updated");
        }
        clientSecretChanges.incrementAndGet();

        return result;
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
        return new ResponseEntity<Void>(HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(ClientAlreadyExistsException.class)
    public ResponseEntity<InvalidClientDetailsException> handleClientAlreadyExists(ClientAlreadyExistsException e) {
        incrementErrorCounts(e);
        return new ResponseEntity<>(new InvalidClientDetailsException(e.getMessage()),
                        HttpStatus.CONFLICT);
    }

    private void incrementErrorCounts(Exception e) {
        String series = UaaStringUtils.getErrorName(e);
        errorCounts.computeIfAbsent(series, k -> new AtomicInteger()).incrementAndGet();
    }


    private void checkPasswordChangeIsAllowed(ClientDetails clientDetails, String oldSecret) {
        String clientId = clientDetails.getClientId();

        // Call is by client
        String currentClientId = securityContextAccessor.getClientId();

        if (!securityContextAccessor.isAdmin() && !securityContextAccessor.getScopes().contains("clients.admin")) {
            if (!clientId.equals(currentClientId)) {
                logger.warn("Client with id " + currentClientId + " attempting to change password for client "
                                + clientId);
                throw new IllegalStateException("Bad request. Not permitted to change another client's secret");
            }

            // Client is changing their own secret, old password is required
            if (!authenticateClient(clientId, oldSecret)) {
                throw new IllegalStateException("Previous secret is required and must be valid");
            }
        }

    }

    private boolean authenticateClient(String clientId, String clientSecret) {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(clientId,clientSecret);
        try {
            HttpServletRequest curRequest =
                ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            if (curRequest != null) {
                authentication.setDetails(new UaaAuthenticationDetails(curRequest, clientId));
            }
        }catch (IllegalStateException x) {
            //ignore - means no thread bound request found
        }
        try {
            Authentication auth = authenticationManager.authenticate(authentication);
            return auth.isAuthenticated();
        } catch (AuthenticationException e) {
            return false;
        } catch (Exception e) {
            logger.debug("Unable to authenticate/validate "+clientId, e);
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

    private ClientDetails syncWithExisting(ClientDetails existing, ClientDetails input) {
        BaseClientDetails details = new BaseClientDetails(input);
        if (input instanceof BaseClientDetails) {
            BaseClientDetails baseInput = (BaseClientDetails)input;
            if (baseInput.getAutoApproveScopes()!=null) {
                details.setAutoApproveScopes(baseInput.getAutoApproveScopes());
            } else {
                details.setAutoApproveScopes(new HashSet<String>());
                if (existing instanceof BaseClientDetails) {
                    BaseClientDetails existingDetails = (BaseClientDetails)existing;
                    if (existingDetails.getAutoApproveScopes()!=null) {
                        for (String scope : existingDetails.getAutoApproveScopes()) {
                            details.getAutoApproveScopes().add(scope);
                        }
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

        Map<String, Object> additionalInformation = new HashMap<String, Object>(existing.getAdditionalInformation());
        additionalInformation.putAll(input.getAdditionalInformation());
        for (String key : Collections.unmodifiableSet(additionalInformation.keySet())) {
            if (additionalInformation.get(key) == null) {
                additionalInformation.remove(key);
            }
        }
        if (Boolean.FALSE.equals(additionalInformation.get(ClientConstants.ALLOW_PUBLIC))) {
            additionalInformation.remove(ClientConstants.ALLOW_PUBLIC);
        }
        details.setAdditionalInformation(additionalInformation);

        return details;
    }

    public void publish(ApplicationEvent event) {
        if (publisher!=null) {
            publisher.publishEvent(event);
        }
    }

    @Override
    public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        publisher = applicationEventPublisher;
    }
}
