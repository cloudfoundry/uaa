package org.cloudfoundry.identity.uaa.zone;

import static org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService.X_IDENTITY_ZONE_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cloudfoundry.identity.uaa.client.ClientDetailsValidator;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.QueryableResourceManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZone;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneRequest;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ArgumentsProvider;
import org.junit.jupiter.params.provider.ArgumentsSource;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
    private ClientDetailsValidator clientDetailsValidator;

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
        clientDetailsValidator = mock(ClientDetailsValidator.class);
        zoneService = new OrchestratorZoneService(zoneProvisioning, idpProvisioning, groupProvisioning,
                                                  clientDetailsService, clientDetailsValidator,
                                                  UAA_DASHBOARD_URI, DOMAIN_NAME);
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        IdentityZoneHolder.set(IdentityZone.getUaa());
    }

    @Test
    public void testGetZoneDetails() {
        IdentityZone identityZone = buildIdentityZone();
        when(zoneProvisioning.retrieveByName(any())).thenReturn(identityZone);
        OrchestratorZoneResponse zone = zoneService.getZoneDetails(ZONE_NAME);
        assertNotNull(zone);
        assertEquals(zone.getName(), ZONE_NAME);
        String uri = "http://" + identityZone.getSubdomain() + ".localhost";
        assertEquals(zone.getParameters().getSubdomain(), identityZone.getSubdomain());
        assertEquals(zone.getConnectionDetails().getSubdomain(), identityZone.getSubdomain());
        assertEquals((zone.getConnectionDetails().getUri()), uri);
        assertEquals(zone.getConnectionDetails().getDashboardUri(), "http://localhost/dashboard");
        assertEquals(zone.getConnectionDetails().getIssuerId(), uri + "/oauth/token");
        assertEquals(zone.getConnectionDetails().getZone().getHttpHeaderName(), X_IDENTITY_ZONE_ID);
        assertEquals(zone.getConnectionDetails().getZone().getHttpHeaderValue(), identityZone.getId());
    }

    @Test
    public void testGetZoneDetails_NotFound() {
        when(zoneProvisioning.retrieveByName(any())).thenThrow(new ZoneDoesNotExistsException("Zone not available."));
        ZoneDoesNotExistsException exception =
            Assertions.assertThrows(ZoneDoesNotExistsException.class, () -> zoneService.getZoneDetails("random-string"),
                                    "Not found exception not thrown");
        assertTrue(exception.getMessage().contains("Zone not available."));
    }

    @Test
    public void testDeleteZone() {
        zoneService.setApplicationEventPublisher(applicationEventPublisher);
        IdentityZone identityZone = buildIdentityZone();
        when(zoneProvisioning.retrieveByName(any())).thenReturn(identityZone);
        ResponseEntity<?> response = zoneService.deleteZone(identityZone.getName());
        assertEquals(HttpStatus.ACCEPTED, response.getStatusCode());
    }

    @Test
    public void testDeleteZone_InternalError() {
        zoneService.setApplicationEventPublisher(null);
        IdentityZone identityZone = buildIdentityZone();
        when(zoneProvisioning.retrieveByName(any())).thenReturn(identityZone);
        ResponseEntity<?> response = zoneService.deleteZone(identityZone.getName());
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    public void testDeleteZone_NotFound() {
        when(zoneProvisioning.retrieveByName(any())).thenThrow(new ZoneDoesNotExistsException("Zone not available."));
        ZoneDoesNotExistsException exception =
            Assertions.assertThrows(ZoneDoesNotExistsException.class, () -> zoneService.deleteZone("random-name"),
                                    "Not found exception not thrown");
        assertTrue(exception.getMessage().contains("Zone not available."));
    }

    private IdentityZone buildIdentityZone() {
        IdentityZone identityZone = new IdentityZone();
        String id = UUID.randomUUID().toString();
        identityZone.setId(id);
        identityZone.setSubdomain(SUB_DOMAIN_NAME);
        identityZone.setName(ZONE_NAME);
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }

    @Test
    public void testCreateZone() throws OrchestratorZoneServiceException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        OrchestratorZoneRequest zoneRequest =  getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET,
                                                                          SUB_DOMAIN_NAME);
        IdentityZone identityZone = createIdentityZone();
        IdentityProvider identityProvider = createDefaultIdp(identityZone);
        when(zoneProvisioning.create(any())).thenReturn(identityZone);
        when(idpProvisioning.create(any(),any())).thenReturn(identityProvider);
        when(clientDetailsService.retrieve(any(),any())).thenReturn(any());
        zoneService.createZone(zoneRequest);
        verify(zoneProvisioning, times(1)).retrieveByName(any());
        verify(zoneProvisioning, times(1)).create(any());
        verify(idpProvisioning, times(1)).create(any(),any());
        verify(clientDetailsService, times(1)).create(any(),any());
        verify(clientDetailsValidator, times(1)).validate(any(),any());
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
    public void testCreateZone_AdminClientSecretEmptyFailWithException() {
        OrchestratorZoneRequest zoneRequest = getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET_EMPTY, SUB_DOMAIN_NAME);
        assertEmptyInputThrowException(zoneRequest);
    }

    private void assertEmptyInputThrowException(OrchestratorZoneRequest zoneRequest) {
        OrchestratorZoneServiceException exception =
            assertThrows(OrchestratorZoneServiceException.class, () ->
                             zoneService.createZone(zoneRequest),
                         "field cannot contain spaces or cannot be blank.");
        assertTrue(exception.getMessage().contains("field cannot contain spaces or cannot be blank."));
    }

    @Test
    public void testCreateZone_SubDomainWithBlankFailWithException() {
        OrchestratorZoneRequest zoneRequest = getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET,
                                                                         SUB_DOMAIN_BLANK_SPACE);
        assertEmptyInputThrowException(zoneRequest);
    }

    @ParameterizedTest
    @ArgumentsSource(SubDomainWithSpaceOrSpecialCharArguments.class)
    public void testCreateZone_SubDomainWithSpaceOrSpecialCharFailWithException(String subDomain) {
        OrchestratorZoneRequest zoneRequest = getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET,
                                                                         subDomain);

        OrchestratorZoneServiceException exception =
            assertThrows(OrchestratorZoneServiceException.class, () ->
                             zoneService.createZone(zoneRequest),
                         "Special characters are not allowed in the subdomain name except hyphen which can be specified in the middle.");
        assertTrue(exception.getMessage().contains("Special characters are not allowed in the subdomain name except hyphen which can be specified in the middle."));
    }

    @Test
    public void testCreateZone_checkOrchestratorZoneExists() {
        OrchestratorZoneRequest zoneRequest = getOrchestratorZoneRequest(ZONE_NAME, ADMIN_CLIENT_SECRET,
                                                                         SUB_DOMAIN_NAME);
        when(zoneProvisioning.retrieveByName(any())).thenReturn(new IdentityZone());
        ZoneAlreadyExistsException exception =
            assertThrows(ZoneAlreadyExistsException.class, () ->
                             zoneService.createZone(zoneRequest),
                         "Orchestrator zone already exists for name");
        assertTrue(exception.getMessage().contains("Orchestrator zone already exists for name"));
    }

    private static class SubDomainWithSpaceOrSpecialCharArguments implements ArgumentsProvider {

        @Override
        public Stream<? extends Arguments> provideArguments(ExtensionContext context) {
            return Stream.of(
                Arguments.of("sub#-domain"),
                Arguments.of("-subdomainStartsWithHYphen"),
                Arguments.of("subdomainEndsWithHYphen-"),
                Arguments.of("sub\\\\domaincontainsslash"),
                Arguments.of("sub$%domaincontainsSpecialChars")
                            );
        }
    }

    private OrchestratorZoneRequest getOrchestratorZoneRequest(String name, String adminClientSecret,
                                                               String subDomain) {
        OrchestratorZoneRequest zoneRequest = new OrchestratorZoneRequest();
        OrchestratorZone zone = new OrchestratorZone(adminClientSecret, subDomain);
        zoneRequest.setName(name);
        zoneRequest.setParameters(zone);
        return zoneRequest;
    }

    private IdentityZone createIdentityZone() {
        IdentityZone identityZone = buildIdentityZone();
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
