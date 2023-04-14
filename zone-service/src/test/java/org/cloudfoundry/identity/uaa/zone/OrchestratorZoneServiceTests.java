package org.cloudfoundry.identity.uaa.zone;

import static org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService.X_IDENTITY_ZONE_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cloudfoundry.identity.uaa.client.ClientAdminEndpointsValidator;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.IdpAlreadyExistsException;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class OrchestratorZoneServiceTests {

    public static final String ZONE_NAME = "The Twiglet Zone";
    public static final String SUB_DOMAIN_NAME = "sub-domain-01";
    public static final String SUB_DOMAIN_BLANK_SPACE = " ";
    public static final String UAA_DASHBOARD_URI = "http://localhost/dashboard";
    public static final String DOMAIN_NAME = "domain-name";
    public static final String ADMIN_CLIENT_SECRET = "admin-secret-01";
    public static final String ADMIN_CLIENT_SECRET_EMPTY = "";
    private OrchestratorZoneService zoneService;
    private IdentityZoneProvisioning zoneProvisioning;
    private IdentityProviderProvisioning idpProvisioning;
    private ScimGroupProvisioning groupProvisioning;
    private QueryableResourceManager<ClientDetails> clientDetailsService;
    private ClientAdminEndpointsValidator clientDetailsValidator;

    private final String serviceProviderKey =
        "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIICXQIBAAKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5\n" +
        "L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vA\n" +
        "fpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQAB\n" +
        "AoGAVOj2Yvuigi6wJD99AO2fgF64sYCm/BKkX3dFEw0vxTPIh58kiRP554Xt5ges\n" +
        "7ZCqL9QpqrChUikO4kJ+nB8Uq2AvaZHbpCEUmbip06IlgdA440o0r0CPo1mgNxGu\n" +
        "lhiWRN43Lruzfh9qKPhleg2dvyFGQxy5Gk6KW/t8IS4x4r0CQQD/dceBA+Ndj3Xp\n" +
        "ubHfxqNz4GTOxndc/AXAowPGpge2zpgIc7f50t8OHhG6XhsfJ0wyQEEvodDhZPYX\n" +
        "kKBnXNHzAkEAyCA76vAwuxqAd3MObhiebniAU3SnPf2u4fdL1EOm92dyFs1JxyyL\n" +
        "gu/DsjPjx6tRtn4YAalxCzmAMXFSb1qHfwJBAM3qx3z0gGKbUEWtPHcP7BNsrnWK\n" +
        "vw6By7VC8bk/ffpaP2yYspS66Le9fzbFwoDzMVVUO/dELVZyBnhqSRHoXQcCQQCe\n" +
        "A2WL8S5o7Vn19rC0GVgu3ZJlUrwiZEVLQdlrticFPXaFrn3Md82ICww3jmURaKHS\n" +
        "N+l4lnMda79eSp3OMmq9AkA0p79BvYsLshUJJnvbk76pCjR28PK4dV1gSDUEqQMB\n" +
        "qy45ptdwJLqLJCeNoR0JUcDNIRhOCuOPND7pcMtX6hI/\n" +
        "-----END RSA PRIVATE KEY-----";

    private final String serviceProviderKeyPassword = "password";

    private final String serviceProviderCertificate =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEO\n" +
        "MAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEO\n" +
        "MAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5h\n" +
        "cnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwx\n" +
        "CzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAM\n" +
        "BgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAb\n" +
        "BgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GN\n" +
        "ADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39W\n" +
        "qS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOw\n" +
        "znoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4Ha\n" +
        "MIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGc\n" +
        "gBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYD\n" +
        "VQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYD\n" +
        "VQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJh\n" +
        "QGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ\n" +
        "0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxC\n" +
        "KdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkK\n" +
        "RpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n" +
        "-----END CERTIFICATE-----\n";


    private IdentityZone mockIdentityZone;
    private ApplicationEventPublisher applicationEventPublisher;

    @BeforeEach
    public void beforeEachTest() {
        mockIdentityZone = mock(IdentityZone.class);
        applicationEventPublisher = mock(ApplicationEventPublisher.class);
        zoneProvisioning = mock(IdentityZoneProvisioning.class);
        idpProvisioning = mock(IdentityProviderProvisioning.class);
        groupProvisioning = mock(ScimGroupProvisioning.class);
        clientDetailsService = mock(QueryableResourceManager.class);
        clientDetailsValidator = mock(ClientAdminEndpointsValidator.class);
        zoneService = new OrchestratorZoneService(zoneProvisioning, idpProvisioning, groupProvisioning,
                                                  clientDetailsService, clientDetailsValidator,
                                                  UAA_DASHBOARD_URI, DOMAIN_NAME);
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        IdentityZoneHolder.set(IdentityZone.getUaa());
    }

    @Test
    public void testGetZoneDetails() {
        OrchestratorZoneEntity orchestratorZone = buildOrchestratorZone();
        when(zoneProvisioning.retrieveByName(any())).thenReturn(orchestratorZone);
        OrchestratorZoneResponse zone = zoneService.getZoneDetails(ZONE_NAME);
        assertNotNull(zone);
        assertEquals(zone.getName(), ZONE_NAME);
        String uri = "http://" + orchestratorZone.getSubdomain() + ".localhost";
        assertEquals(zone.getConnectionDetails().getSubdomain(), orchestratorZone.getSubdomain());
        assertEquals((zone.getConnectionDetails().getUri()), uri);
        assertEquals(zone.getConnectionDetails().getDashboardUri(), "http://localhost/dashboard");
        assertEquals(zone.getConnectionDetails().getIssuerId(), uri + "/oauth/token");
        assertEquals(zone.getConnectionDetails().getZone().getHttpHeaderName(), X_IDENTITY_ZONE_ID);
        assertEquals(zone.getConnectionDetails().getZone().getHttpHeaderValue(), orchestratorZone.getIdentityZoneId());
        assertTrue(zone.getMessage().isEmpty());
        assertEquals(OrchestratorState.FOUND.toString(), zone.getState());
    }

    @Test
    public void testGetZoneDetails_NotFound() {
        when(zoneProvisioning.retrieveByName(any())).thenThrow(
                new ZoneDoesNotExistsException("random-string", "Zone not available.", new Throwable()));
        ZoneDoesNotExistsException exception =
            Assertions.assertThrows(ZoneDoesNotExistsException.class, () -> zoneService.getZoneDetails("random-string"),
                                    "Not found exception not thrown");
        assertTrue(exception.getMessage().contains("Zone not available."));
        assertEquals("random-string", exception.getZoneName());
    }

    @Test
    public void testDeleteZone() throws Exception {
        zoneService.setApplicationEventPublisher(applicationEventPublisher);
        OrchestratorZoneEntity orchestratorZone = buildOrchestratorZone();
        when(zoneProvisioning.retrieveByName(any())).thenReturn(orchestratorZone);
        when(zoneProvisioning.retrieve(any())).thenReturn(createIdentityZone(orchestratorZone.getIdentityZoneId()));
        zoneService.deleteZone(orchestratorZone.getOrchestratorZoneName());
        verify(zoneProvisioning, times(1)).retrieveByName(any());
        verify(applicationEventPublisher, times(1)).publishEvent(any());
    }

    @Test
    public void testDeleteZone_InternalError() {
        zoneService.setApplicationEventPublisher(null);
        OrchestratorZoneEntity orchestratorZone = buildOrchestratorZone();
        when(zoneProvisioning.retrieveByName(any())).thenReturn(orchestratorZone);
        Assertions.assertThrows(Exception.class, () -> zoneService.deleteZone(orchestratorZone.getOrchestratorZoneName()),
                                "Zone - deleting Name[" + orchestratorZone.getOrchestratorZoneName() + "]");
    }

    @Test
    public void testDeleteZone_NotFound() {
        when(zoneProvisioning.retrieveByName(any())).thenThrow(new ZoneDoesNotExistsException("Zone not available."));
        ZoneDoesNotExistsException exception =
            Assertions.assertThrows(ZoneDoesNotExistsException.class, () -> zoneService.deleteZone("random-name"),
                                    "Not found exception not thrown");
        assertTrue(exception.getMessage().contains("Zone not available."));
    }

    private OrchestratorZoneEntity buildOrchestratorZone() {
        OrchestratorZoneEntity orchestratorZone = new OrchestratorZoneEntity();
        String id = UUID.randomUUID().toString();
        orchestratorZone.setIdentityZoneId(id);
        orchestratorZone.setSubdomain(SUB_DOMAIN_NAME);
        orchestratorZone.setOrchestratorZoneName(ZONE_NAME);
        return orchestratorZone;
    }

    @Test
    public void testCreateZone_createZoneAdminClient_ExceptionCheck() {
        Security.addProvider(new BouncyCastleProvider());
        OrchestratorZoneRequest zoneRequest =  getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET,
                                                                          SUB_DOMAIN_NAME);
        IdentityZone identityZone = createIdentityZone(null);
        IdentityProvider identityProvider = createDefaultIdp(identityZone);
        when(zoneProvisioning.create(any())).thenReturn(identityZone);
        when(idpProvisioning.create(any(),any())).thenReturn(identityProvider);
        when(clientDetailsService.create(any(),any())).thenThrow(new OrchestratorZoneServiceException("Client Already exists"));
        Assertions.assertThrows(OrchestratorZoneServiceException.class, () -> zoneService.createZone(zoneRequest),
                                "Client Already exists exception not thrown");
        verify(idpProvisioning, times(1)).create(any(),any());
        verify(clientDetailsService, times(1)).create(any(),any());
        verify(clientDetailsValidator, times(1)).validate(any(),anyBoolean(),anyBoolean());
    }

    @Test
    public void testCreateZone_createDefaultIdp_ExceptionCheck() throws OrchestratorZoneServiceException {
        Security.addProvider(new BouncyCastleProvider());
        OrchestratorZoneRequest zoneRequest =  getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET,
                                                                          SUB_DOMAIN_NAME);
        IdentityZone identityZone = createIdentityZone(null);
        IdentityProvider identityProvider = createDefaultIdp(identityZone);
        when(zoneProvisioning.create(any())).thenReturn(identityZone);
        when(idpProvisioning.create(any(),any())).thenThrow(new IdpAlreadyExistsException("IDP Already exists"));
        when(clientDetailsService.create(any(),any())).thenReturn(any());

        Assertions.assertThrows(OrchestratorZoneServiceException.class, () -> zoneService.createZone(zoneRequest),
                                "IDP Already exists exception not thrown");
    }

    @Test
    public void testCreateZone_createIdentityZone_ExceptionCheck() throws OrchestratorZoneServiceException {
        Security.addProvider(new BouncyCastleProvider());
        OrchestratorZoneRequest zoneRequest =  getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET,
                                                                          SUB_DOMAIN_NAME);
        IdentityZone identityZone = createIdentityZone(null);
        IdentityProvider identityProvider = createDefaultIdp(identityZone);
        when(zoneProvisioning.create(any())).thenThrow(new ZoneAlreadyExistsException("Identity Zone Already exists"));
        when(idpProvisioning.create(any(),any())).thenReturn(identityProvider);
        when(clientDetailsService.create(any(),any())).thenReturn(any());

        Assertions.assertThrows(ZoneAlreadyExistsException.class, () -> zoneService.createZone(zoneRequest),
                                "Identity Zone Already exists exception not thrown");
    }

    @Test
    public void testCreateZone() throws OrchestratorZoneServiceException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        OrchestratorZoneRequest zoneRequest =  getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET,
                                                                          SUB_DOMAIN_NAME);
        IdentityZone identityZone = createIdentityZone(null);
        IdentityProvider identityProvider = createDefaultIdp(identityZone);
        when(zoneProvisioning.create(any())).thenReturn(identityZone);
        when(idpProvisioning.create(any(),any())).thenReturn(identityProvider);
        when(clientDetailsService.retrieve(any(),any())).thenReturn(any());
        zoneService.createZone(zoneRequest);
        verify(zoneProvisioning, times(1)).create(any());
        verify(idpProvisioning, times(1)).create(any(),any());
        verify(clientDetailsService, times(1)).create(any(),any());
        verify(clientDetailsValidator, times(1)).validate(any(),anyBoolean(),anyBoolean());
    }

    @Test
    public void testGenerateIdentityZone() throws OrchestratorZoneServiceException, IOException, InvalidIdentityZoneDetailsException {
        Security.addProvider(new BouncyCastleProvider());

        MfaConfigValidator mfaConfigValidator = mock(MfaConfigValidator.class);
        GeneralIdentityZoneConfigurationValidator configValidator = new GeneralIdentityZoneConfigurationValidator(mfaConfigValidator);
        GeneralIdentityZoneValidator validator = new GeneralIdentityZoneValidator(configValidator);

        IdentityZone identityZone = zoneService.generateIdentityZone(ZONE_NAME, SUB_DOMAIN_NAME, UUID.randomUUID().toString());
        validator.validate(identityZone, IdentityZoneValidator.Mode.CREATE);
    }

    @Test
    public void testCreateZoneDetails_AccessDeniedException() {
        when(mockIdentityZone.getId()).thenReturn("not uaa");
        IdentityZoneHolder.set(mockIdentityZone);
        OrchestratorZoneRequest zoneRequest =  getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET,
                                                                          SUB_DOMAIN_NAME);
        AccessDeniedException exception =
            assertThrows(AccessDeniedException.class, () ->
                             zoneService.createZone(zoneRequest),
                         "Zones can only be created by being " +
                         "authenticated in the default zone.");
        assertTrue(exception.getMessage().contains("Zones can only be created by being " +
                                                   "authenticated in the default zone."));
    }

    @Test
    public void testCreateZone_DuplicateSubdomainCauseZoneAlreadyExistsException () {
        Security.addProvider(new BouncyCastleProvider());
        OrchestratorZoneRequest zoneRequest =  getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET,
                                                                          SUB_DOMAIN_NAME);
        when(zoneProvisioning.create(any())).thenReturn(createIdentityZone(null));
        String errorMessage = String.format("The subdomain name %s is already taken. Please use a different subdomain",
                                            zoneRequest.getParameters().getSubdomain());
        when(zoneProvisioning.create(any())).thenThrow(new ZoneAlreadyExistsException(errorMessage));
        ZoneAlreadyExistsException exception =
            assertThrows(ZoneAlreadyExistsException.class, () ->
                             zoneService.createZone(zoneRequest),
                         errorMessage);
        assertTrue(exception.getMessage().contains(errorMessage));
        verify(zoneProvisioning, times(1)).create(any());
    }


    private OrchestratorZoneRequest getOrchestratorZoneRequest(String name, String adminClientSecret,
                                                               String subDomain) {
        OrchestratorZoneRequest zoneRequest = new OrchestratorZoneRequest();
        OrchestratorZone zone = new OrchestratorZone(adminClientSecret, subDomain);
        zoneRequest.setName(name);
        zoneRequest.setParameters(zone);
        return zoneRequest;
    }

    private IdentityZone createIdentityZone(String id) {
        IdentityZone identityZone = new IdentityZone();
        if (id == null) {
            id = UUID.randomUUID().toString();
        }
        identityZone.setId(id);
        identityZone.setSubdomain(SUB_DOMAIN_NAME);
        identityZone.setName(ZONE_NAME);
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        IdentityZoneConfiguration identityZoneConfiguration = new IdentityZoneConfiguration();
        Map<String, String> keys = new HashMap<>();
        keys.put("kid", "key");
        identityZoneConfiguration.getTokenPolicy().setKeys(keys);
        identityZoneConfiguration.getTokenPolicy().setActiveKeyId("kid");
        identityZoneConfiguration.getTokenPolicy().setKeys(keys);

        identityZone.setConfig(identityZoneConfiguration);
        identityZone.getConfig().getSamlConfig().setPrivateKey(serviceProviderKey);
        identityZone.getConfig().getSamlConfig().setPrivateKeyPassword(serviceProviderKeyPassword);
        identityZone.getConfig().getSamlConfig().setCertificate(serviceProviderCertificate);

        return identityZone;
    }

    private IdentityProvider createDefaultIdp(IdentityZone created) {
        IdentityProvider defaultIdp = new IdentityProvider();
        defaultIdp.setName(OriginKeys.UAA);
        defaultIdp.setType(OriginKeys.UAA);
        defaultIdp.setOriginKey(OriginKeys.UAA);
        defaultIdp.setIdentityZoneId(created.getId());
        UaaIdentityProviderDefinition idpDefinition = new UaaIdentityProviderDefinition();
        idpDefinition.setPasswordPolicy(null);
        defaultIdp.setConfig(idpDefinition);
        return defaultIdp;
    }
}
