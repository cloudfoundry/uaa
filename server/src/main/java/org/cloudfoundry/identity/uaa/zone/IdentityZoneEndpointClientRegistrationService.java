package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.ClientRegistrationService;

public class IdentityZoneEndpointClientRegistrationService {

    private final ClientRegistrationService clientRegistrationService;
    private final ClientDetailsService clientDetailsService;
    private final ClientDetailsValidator clientDetailsValidator;
    private final ApprovalStore approvalStore;


    public IdentityZoneEndpointClientRegistrationService(ClientRegistrationService clientRegistrationService,
            ClientDetailsService clientDetailsService, ClientDetailsValidator clientDetailsValidator,
            ApprovalStore approvalStore) {
        super();
        this.clientRegistrationService = clientRegistrationService;
        this.clientDetailsService = clientDetailsService;
        this.clientDetailsValidator = clientDetailsValidator;
        this.approvalStore = approvalStore;
    }

    public ClientDetails createClient(ClientDetails clientDetails) {
        ClientDetails validated = clientDetailsValidator.validate(clientDetails, Mode.CREATE);
        clientRegistrationService.addClientDetails(validated);
        return validated;
    }

    public ClientDetails deleteClient(String clientId) {
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId);
        clientDetailsValidator.validate(clientDetails, Mode.DELETE);
        clientRegistrationService.removeClientDetails(clientId);
        approvalStore.revokeApprovalsForClient(clientId);
        return clientDetails;
    }
}