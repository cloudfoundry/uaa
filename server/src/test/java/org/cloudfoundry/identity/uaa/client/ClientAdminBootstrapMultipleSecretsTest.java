package org.cloudfoundry.identity.uaa.client;

import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientAdminBootstrapMultipleSecretsTest {

    private ClientAdminBootstrap clientAdminBootstrap;
    private Map<String, Map<String, Object>> clients;
    private UaaClientDetails verifyClient;
    private final String clientId = "client1";
    private String password1;
    private String password2;
    private MultitenantClientServices clientRegistrationService;
    private UaaClientDetails oneSecretClient;
    private UaaClientDetails twoSecretClient;

    @BeforeEach
    void setUp() {
        Set<String> clientsToDelete = new HashSet<>();
        boolean defaultOverride = true;
        Set<String> autoApproveClients = new HashSet<>();
        Set<String> allowPublicClients = new HashSet<>();
        clients = new HashMap<>();

        PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);

        clientRegistrationService = mock(MultitenantClientServices.class);
        doAnswer(invocation -> {
            verifyClient.setClientId(invocation.getArgument(0));
            verifyClient.setClientSecret(invocation.getArgument(1));
            return null;
        }).when(clientRegistrationService).updateClientSecret(anyString(), anyString(), anyString());

        doAnswer(invocation -> {
            verifyClient = invocation.getArgument(0);
            return null;
        }).when(clientRegistrationService).updateClientDetails(any(), any());

        doAnswer(invocation -> {
            String password = verifyClient.getClientSecret();
            verifyClient.setClientSecret(password + " " + invocation.getArgument(1));
            return null;
        }).when(clientRegistrationService).addClientSecret(anyString(), anyString(), anyString());

        doAnswer(invocation -> {
            verifyClient = invocation.getArgument(0);
            return null;
        }).when(clientRegistrationService).addClientDetails(any(), any());

        ClientMetadataProvisioning clientMetadataProvisioning = mock(ClientMetadataProvisioning.class);

        clientAdminBootstrap = new ClientAdminBootstrap(passwordEncoder, clientRegistrationService, clientMetadataProvisioning, defaultOverride, clients, autoApproveClients, clientsToDelete, null,
                allowPublicClients);

        oneSecretClient = new UaaClientDetails();
        oneSecretClient.setClientId(clientId);
        oneSecretClient.setClientSecret("oldOneSecret");

        twoSecretClient = new UaaClientDetails();
        twoSecretClient.setClientId(clientId);
        String oldOneSecret = "oldOneSecret";
        String oldTwoSecret = "oldTwoSecret";
        twoSecretClient.setClientSecret(oldOneSecret + " " + oldTwoSecret);
    }

    /*
     * Test cases for new clients, existing client with 1 password and existing clients with 2 passwords:
     * - one password
     * - one password null
     * - two passwords
     * - two passwords, first null
     * - two passwords, second null
     * - two passwords, both null
     * - empty password list
     * - one password list
     * - one password list null
     */

    // Test one secret
    @Test
    void newClientOneSecret() {
        buildClient("123");
        clientAdminBootstrap.afterPropertiesSet();
        assertClient(password1);
    }

    @Test
    void updateOneSecretClientOneSecret() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
        newClientOneSecret();
    }

    @Test
    void updateTwoSecretClientOneSecret() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
        newClientOneSecret();
    }

    // test one null secret
    @Test
    void newClientOneNullSecret() {
        buildClient(null);
        clientAdminBootstrap.afterPropertiesSet();
        assertClient(null);
    }

    @Test
    void updateOneSecretClientOneNullSecret() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
        newClientOneNullSecret();
    }

    @Test
    void updateTwoSecretClientOneNullSecret() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
        newClientOneNullSecret();
    }

    // Test two secrets
    @Test
    void newClientTwoSecrets() {
        buildClientList("123", "abc");
        clientAdminBootstrap.afterPropertiesSet();
        assertClient(password1 + " " + password2);
    }

    @Test
    void updateOneSecretClientTwoSecrets() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
        newClientTwoSecrets();
    }

    @Test
    void updateTwoSecretClientTwoSecrets() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
        newClientTwoSecrets();
    }

    // Test two passwords, first null
    @Test
    void newClientFirstNullSecret() {
        buildClientList(null, "123");
        clientAdminBootstrap.afterPropertiesSet();
        assertClient(" " + password2);
    }

    @Test
    void updateOneSecretClientFirstNullSecret() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
        newClientFirstNullSecret();
    }

    @Test
    void updateTwoSecretClientFirstNullSecret() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
        newClientFirstNullSecret();
    }

    // Test two passwords, second null
    @Test
    void newClientSecondNullSecret() {
        buildClientList("123", null);
        clientAdminBootstrap.afterPropertiesSet();
        assertClient(password1 + " ");
    }

    @Test
    void updateOneSecretClientSecondNullSecret() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
        newClientSecondNullSecret();
    }

    @Test
    void updateTwoSecretClientSecondNullSecret() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
        newClientSecondNullSecret();
    }

    // Test two secrets, both nulls
    @Test
    void newClientBothNullSecrets() {
        buildClientList(null, null);
        clientAdminBootstrap.afterPropertiesSet();
        assertClient(" ");
    }

    @Test
    void updateOneSecretClientBothNullSecrets() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
        newClientBothNullSecrets();
    }

    @Test
    void updateTwoSecretClientBothNullSecrets() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
        newClientBothNullSecrets();
    }

    // Test empty password list
    @Test
    void newClientEmptyPasswordList() {
        buildClient(null);
        clients.get(clientId).put("secret", new LinkedList<>());
        clientAdminBootstrap.afterPropertiesSet();
        assertClient(null);
    }

    @Test
    void updateOnePasswordClientEmptyPasswordList() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
        newClientEmptyPasswordList();
    }

    @Test
    void updateTwoPasswordClientEmptyPasswordList() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
        newClientEmptyPasswordList();
    }

    // Test one password as a list
    @Test
    void newClientSingletonPasswordList() {
        buildClientSingletonList("123");
        clientAdminBootstrap.afterPropertiesSet();
        assertClient(password1);
    }

    @Test
    void updateOneSecretClientSingletonPasswordList() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
        newClientSingletonPasswordList();
    }

    @Test
    void updateTwoSecretClientSingletonPasswordList() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
        newClientSingletonPasswordList();
    }

    // Test one null password as a list
    @Test
    void newClientSingletonNullList() {
        buildClientSingletonList(null);
        clientAdminBootstrap.afterPropertiesSet();
        assertClient("");
    }

    @Test
    void updateOneSecretClientSingletonNullList() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
        newClientSingletonNullList();
    }

    @Test
    void updateTwoSecretClientSingletonNullList() {
        when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
        newClientSingletonNullList();
    }

    private void assertClient(String password) {
        assertThat(verifyClient.getClientId()).isEqualTo(clientId);
        assertThat(verifyClient.getClientSecret()).isEqualTo(password);
    }

    private void buildClientSingletonList(String password1) {
        this.password1 = password1;
        Map<String, Object> client = new HashMap<>();
        List<String> secrets = new LinkedList<>();
        secrets.add(password1);
        client.put("secret", secrets);
        client.put("authorized-grant-types", "password");
        clients.put(clientId, client);
    }

    private void buildClientList(String password1, String password2) {
        this.password1 = password1;
        this.password2 = password2;
        Map<String, Object> client = new HashMap<>();
        List<String> secrets = new LinkedList<>();
        secrets.add(password1);
        secrets.add(password2);
        client.put("secret", secrets);
        client.put("authorized-grant-types", "password");
        clients.put(clientId, client);
    }

    private void buildClient(String password1) {
        this.password1 = password1;
        Map<String, Object> client = new HashMap<>();
        client.put("secret", password1);
        client.put("authorized-grant-types", "password");
        clients.put(clientId, client);
    }
}
