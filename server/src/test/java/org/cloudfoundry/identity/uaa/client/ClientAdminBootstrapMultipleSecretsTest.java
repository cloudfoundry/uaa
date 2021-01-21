package org.cloudfoundry.identity.uaa.client;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.stubbing.Answer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

public class ClientAdminBootstrapMultipleSecretsTest {

	private ClientAdminBootstrap clientAdminBootstrap;
	private Map<String, Map<String, Object>> clients;
	private BaseClientDetails verifyClient;
	private String clientId = "client1";
	private String password1;
	private String password2;
	private String oldOneSecret = "oldOneSecret";
	private String oldTwoSecret = "oldTwoSecret";
	private MultitenantClientServices clientRegistrationService;
	private BaseClientDetails oneSecretClient;
	private BaseClientDetails twoSecretClient;

	@Before
	public void setUp() {
		Set<String> clientsToDelete = new HashSet<>();
		boolean defaultOverride = true;
		Set<String> autoApproveClients = new HashSet<>();
		clients = new HashMap<>();

		PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);

		clientRegistrationService = mock(MultitenantClientServices.class);
		doAnswer((Answer) invocation -> {
			verifyClient.setClientId(invocation.getArgument(0));
			verifyClient.setClientSecret(invocation.getArgument(1));
			return null;
		}).when(clientRegistrationService).updateClientSecret(anyString(), anyString(), anyString());

		doAnswer((Answer) invocation -> {
			verifyClient = invocation.getArgument(0);
			return null;
		}).when(clientRegistrationService).updateClientDetails(any(), any());

		doAnswer((Answer) invocation -> {
			String password = verifyClient.getClientSecret();
			verifyClient.setClientSecret(password + " " + invocation.getArgument(1));
			return null;
		}).when(clientRegistrationService).addClientSecret(anyString(), anyString(), anyString());

		doAnswer((Answer) invocation -> {
			verifyClient = invocation.getArgument(0);
			return null;
		}).when(clientRegistrationService).addClientDetails(any(), any());

		ClientMetadataProvisioning clientMetadataProvisioning = mock(ClientMetadataProvisioning.class);

		clientAdminBootstrap = new ClientAdminBootstrap(passwordEncoder, clientRegistrationService, clientMetadataProvisioning, defaultOverride, clients, autoApproveClients, clientsToDelete, null);

		oneSecretClient = new BaseClientDetails();
		oneSecretClient.setClientId(clientId);
		oneSecretClient.setClientSecret("oldOneSecret");

		twoSecretClient = new BaseClientDetails();
		twoSecretClient.setClientId(clientId);
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
	public void newClientOneSecret() throws Exception {
		buildClient("123");
		clientAdminBootstrap.afterPropertiesSet();
		assertClient(password1);
	}

	@Test
	public void updateOneSecretClientOneSecret() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
		newClientOneSecret();
	}

	@Test
	public void updateTwoSecretClientOneSecret() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
		newClientOneSecret();
	}

	// test one null secret
	@Test
	public void newClientOneNullSecret() throws Exception {
		buildClient(null);
		clientAdminBootstrap.afterPropertiesSet();
		assertClient(null);
	}

	@Test
	public void updateOneSecretClientOneNullSecret() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
		newClientOneNullSecret();
	}

	@Test
	public void updateTwoSecretClientOneNullSecret() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
		newClientOneNullSecret();
	}


	// Test two secrets
	@Test
	public void newClientTwoSecrets() throws Exception {
		buildClientList("123", "abc");
		clientAdminBootstrap.afterPropertiesSet();
		assertClient(password1 + " " + password2);
	}

	@Test
	public void updateOneSecretClientTwoSecrets() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
		newClientTwoSecrets();
	}

	@Test
	public void updateTwoSecretClientTwoSecrets() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
		newClientTwoSecrets();
	}

	// Test two passwords, first null
	@Test
	public void newClientFirstNullSecret() throws Exception {
		buildClientList(null, "123");
		clientAdminBootstrap.afterPropertiesSet();
		assertClient(" " + password2);
	}

	@Test
	public void updateOneSecretClientFirstNullSecret() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
		newClientFirstNullSecret();
	}

	@Test
	public void updateTwoSecretClientFirstNullSecret() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
		newClientFirstNullSecret();
	}

	// Test two passwords, second null
	@Test
	public void newClientSecondNullSecret() throws Exception {
		buildClientList("123", null);
		clientAdminBootstrap.afterPropertiesSet();
		assertClient(password1 + " ");
	}

	@Test
	public void updateOneSecretClientSecondNullSecret() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
		newClientSecondNullSecret();
	}

	@Test
	public void updateTwoSecretClientSecondNullSecret() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
		newClientSecondNullSecret();
	}

	// Test two secrets, both null
	@Test
	public void newClientBothNullSecrets() throws Exception {
		buildClientList(null, null);
		clientAdminBootstrap.afterPropertiesSet();
		assertClient(" ");
	}

	@Test
	public void updateOneSecretClientBothNullSecrets() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
		newClientBothNullSecrets();
	}

	@Test
	public void updateTwoSecretClientBothNullSecrets() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
		newClientBothNullSecrets();
	}

	// Test empty password list
	@Test
	public void newClientEmptyPasswordList() throws Exception {
		buildClient(null);
		clients.get(clientId).put("secret", new LinkedList<>());
		clientAdminBootstrap.afterPropertiesSet();
		assertClient("");
	}

	@Test
	public void updateOnePasswordClientEmptyPasswordList() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
		newClientEmptyPasswordList();
	}

	@Test
	public void updateTwoPasswordClientEmptyPaswordList() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
		newClientEmptyPasswordList();
	}

	// Test one password as list
	@Test
	public void newClientSingletonPasswordList() throws Exception {
		buildClientSingletonList("123");
		clientAdminBootstrap.afterPropertiesSet();
		assertClient(password1);
	}

	@Test
	public void updateOneSecretClientSingletonPasswordList() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
		newClientSingletonPasswordList();
	}

	@Test
	public void updateTwoSecretClientSingletonPasswordList() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
		newClientSingletonPasswordList();
	}

	// Test one null password as list
	@Test
	public void newClientSingletonNullList() throws Exception {
		buildClientSingletonList(null);
		clientAdminBootstrap.afterPropertiesSet();
		assertClient("");
	}

	@Test
	public void updateOneSecretClientSingletonNullList() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(oneSecretClient);
		newClientSingletonNullList();
	}

	@Test
	public void updateTwoSecretClientSingletonNullList() throws Exception {
		when(clientRegistrationService.loadClientByClientId(any(), any())).thenReturn(twoSecretClient);
		newClientSingletonNullList();
	}

	private void assertClient(String password) {
		Assert.assertEquals(clientId, verifyClient.getClientId());
		Assert.assertEquals(password == null ? "" : password, verifyClient.getClientSecret());
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
