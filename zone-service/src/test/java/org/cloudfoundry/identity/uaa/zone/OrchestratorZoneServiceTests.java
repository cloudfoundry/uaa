package org.cloudfoundry.identity.uaa.zone;

import static org.cloudfoundry.identity.uaa.zone.OrchestratorZoneService.X_IDENTITY_ZONE_ID;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import net.bytebuddy.utility.RandomString;
import org.cloudfoundry.identity.uaa.zone.model.OrchestratorZoneResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public class OrchestratorZoneServiceTests {

    public static final String ZONE_NAME = "The Twiglet Zone";
    private OrchestratorZoneService zoneService;
    private IdentityZoneProvisioning zoneProvisioning;

    @BeforeEach
    public void beforeEachTest() {
        zoneProvisioning = Mockito.mock(IdentityZoneProvisioning.class);
        zoneService = new OrchestratorZoneService(zoneProvisioning, "http://localhost/dashboard");
        zoneService.setApplicationEventPublisher(mock(ApplicationEventPublisher.class));
        MockHttpServletRequest request = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
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
        identityZone.setId(RandomString.make(10));
        identityZone.setSubdomain(RandomString.make(10).toLowerCase());
        identityZone.setName(ZONE_NAME);
        identityZone.setDescription("Like the Twilight Zone but tastier.");
        return identityZone;
    }
}
