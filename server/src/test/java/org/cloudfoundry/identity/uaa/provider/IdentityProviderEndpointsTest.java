package org.cloudfoundry.identity.uaa.provider;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.scim.ScimGroupExternalMembershipManager;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.junit.Assert.*;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IdentityProviderEndpointsTest {

    private IdentityProviderEndpoints identityProviderEndpoints;
    private IdentityProviderProvisioning identityProviderProvisioning;
    private ScimGroupExternalMembershipManager scimGroupExternalMembershipManager;
    private ScimGroupProvisioning scimGroupProvisioning;
    private SamlIdentityProviderConfigurator samlConfigurator;
    private IdentityProviderConfigValidationDelegator configValidator;

    @Before
    public void setup() {
        identityProviderProvisioning = mock(IdentityProviderProvisioning.class);
        identityProviderEndpoints = new IdentityProviderEndpoints(identityProviderProvisioning, scimGroupExternalMembershipManager, scimGroupProvisioning, samlConfigurator, configValidator);
    }

    @Test
    public void testPatchIdentityProviderStatusInvalidPayload () {
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
    }

    @Test
    public void testPatchIdentityProviderStatusInvalidIDP () {
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider notUAAIDP = new IdentityProvider();
        notUAAIDP.setType("NOT_UAA");
        notUAAIDP.setConfig(new SamlIdentityProviderDefinition());
        when(identityProviderProvisioning.retrieve(anyString())).thenReturn(notUAAIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
    }

    @Test
    public void testPatchIdentityProviderStatusWithNoIDPDefinition () {
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider invalidIDP = new IdentityProvider();
        invalidIDP.setConfig(null);
        invalidIDP.setType(OriginKeys.UAA);
        when(identityProviderProvisioning.retrieve(anyString())).thenReturn(invalidIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
    }

    @Test
    public void testPatchIdentityProviderStatusWithNoPasswordPolicy () {
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider invalidIDP = new IdentityProvider();
        invalidIDP.setType(OriginKeys.UAA);
        invalidIDP.setConfig(new UaaIdentityProviderDefinition(null, null));
        when(identityProviderProvisioning.retrieve(anyString())).thenReturn(invalidIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.BAD_REQUEST, responseEntity.getStatusCode());
    }

    @Test
    public void testPatchIdentityProviderStatus () {
        IdentityProviderStatus identityProviderStatus = new IdentityProviderStatus();
        identityProviderStatus.setRequirePasswordChange(true);
        IdentityProvider validIDP = new IdentityProvider();
        validIDP.setType(OriginKeys.UAA);
        validIDP.setConfig(new UaaIdentityProviderDefinition(new PasswordPolicy(), null));
        when(identityProviderProvisioning.retrieve(anyString())).thenReturn(validIDP);
        ResponseEntity responseEntity = identityProviderEndpoints.updateIdentityProviderStatus("123", identityProviderStatus);
        assertEquals(HttpStatus.OK, responseEntity.getStatusCode());
    }
}