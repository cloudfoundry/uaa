package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator.Mode;
import org.cloudfoundry.identity.uaa.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.ClientDetails;

public class IdentityZoneEndpointClientRegistrationService {

    private final MultitenantClientServices clientDetailsService;
    private final ClientDetailsValidator clientDetailsValidator;
    private final ApprovalStore approvalStore;


    public IdentityZoneEndpointClientRegistrationService(MultitenantClientServices clientDetailsService,
                                                         ClientDetailsValidator clientDetailsValidator,
                                                         ApprovalStore approvalStore) {
        super();
        this.clientDetailsService = clientDetailsService;
        this.clientDetailsValidator = clientDetailsValidator;
        this.approvalStore = approvalStore;
    }

    public ClientDetails createClient(ClientDetails clientDetails) {
        ClientDetails validated = clientDetailsValidator.validate(clientDetails, Mode.CREATE);
        clientDetailsService.addClientDetails(validated, IdentityZoneHolder.get().getId());
        return validated;
    }

    public ClientDetails deleteClient(String clientId) {
        String zoneId = IdentityZoneHolder.get().getId();
        ClientDetails clientDetails = clientDetailsService.loadClientByClientId(clientId, zoneId);
        clientDetailsValidator.validate(clientDetails, Mode.DELETE);
        clientDetailsService.removeClientDetails(clientId, zoneId);
        approvalStore.revokeApprovalsForClient(clientId, zoneId);
        return clientDetails;
    }
}