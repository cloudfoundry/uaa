package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigAlreadyExistsException;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigDoesNotExistException;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MfaConfig;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class UserGoogleMfaCredentialsProvisioningTest {

    UserGoogleMfaCredentialsProvisioning provisioner;
    JdbcUserGoogleMfaCredentialsProvisioning jdbcProvisioner;
    MfaProviderProvisioning mfaProviderProvisioning;
    private MfaProvider mfaProvider;
    private MfaProvider otherMfaProvider;

    @Before
    public void setup() {
        provisioner = new UserGoogleMfaCredentialsProvisioning();
        mfaProvider = new MfaProvider().setName("abc").setId("abc");
        otherMfaProvider = new MfaProvider().setName("abcd").setId("abcd");
        jdbcProvisioner = mock(JdbcUserGoogleMfaCredentialsProvisioning.class);
        provisioner.setJdbcProvisioner(jdbcProvisioner);
        mfaProviderProvisioning = mock(MfaProviderProvisioning.class);
        provisioner.setMfaProviderProvisioning(mfaProviderProvisioning);
        when(mfaProviderProvisioning.retrieveByName(anyString(), anyString())).thenReturn(mfaProvider);
        IdentityZoneHolder.get().getConfig().setMfaConfig(new MfaConfig().setEnabled(true).setProviderName(mfaProvider.getName()));
    }

    @After
    public void teardown() throws Exception {
        IdentityZoneHolder.clear();
    }

    @Test
    public void testSavesCredentialsNotInDatabase() {
        UserGoogleMfaCredentials creds = creds();
        provisioner.saveUserCredentials(creds.getUserId(), creds.getSecretKey(), creds.getValidationCode(), creds.getScratchCodes());
        verify(jdbcProvisioner, times(0)).save(any(), anyString());
    }

    @Test
    public void testSaveUserCredentials_updatesWhenUserExists() {
        UserGoogleMfaCredentials creds = creds();
        provisioner.saveUserCredentials(creds.getUserId(), creds.getSecretKey(), creds.getValidationCode(), creds.getScratchCodes());

        UserGoogleMfaCredentials updatedCreds = new UserGoogleMfaCredentials("jabbahut",
                                                                             "different_key",
                                                                             45678,
                                                                             Arrays.asList(1, 22));

        provisioner.saveUserCredentials(updatedCreds.getUserId(), updatedCreds.getSecretKey(), updatedCreds.getValidationCode(), updatedCreds.getScratchCodes());
        verify(jdbcProvisioner, times(0)).save(any(), anyString());
    }

    @Test
    public void testPersist() {
        UserGoogleMfaCredentials creds = creds();
        provisioner.saveUserCredentials(creds.getUserId(), creds.getSecretKey(), creds.getValidationCode(), creds.getScratchCodes());
        verify(jdbcProvisioner, times(0)).save(any(), anyString());
        provisioner.saveUserCredentials(creds);
        verify(jdbcProvisioner, times(1)).save(creds, IdentityZoneHolder.get().getId());
    }

    @Test
    public void testPersist_emptySession() {
        //provisioner.persistCredentials();
        verify(jdbcProvisioner, times(0)).save(any(), anyString());
        //assume that creds are already in database if session doesn't exist
    }

    @Test(expected = UserMfaConfigAlreadyExistsException.class)
    public void testPersist_ErrorsIfAlreadyExists() {
        UserGoogleMfaCredentials creds = creds();
        provisioner.saveUserCredentials(creds.getUserId(), creds.getSecretKey(), creds.getValidationCode(), creds.getScratchCodes());
        verify(jdbcProvisioner, times(0)).save(any(), anyString());
        provisioner.saveUserCredentials(creds);
        doThrow(UserMfaConfigAlreadyExistsException.class).when(jdbcProvisioner).save(any(), anyString());
        provisioner.saveUserCredentials(creds);
    }

    @Test
    public void testActiveUserCredentialExists() {
        UserGoogleMfaCredentials creds = creds();
        when(jdbcProvisioner.retrieve(anyString(), eq(mfaProvider.getId()))).thenReturn(creds);
        when(jdbcProvisioner.retrieve(anyString(), eq(otherMfaProvider.getId()))).thenThrow(UserMfaConfigDoesNotExistException.class);

        provisioner.saveUserCredentials(creds.getUserId(), creds.getSecretKey(), creds.getValidationCode(), creds.getScratchCodes());

        //provisioner.persistCredentials();

        assertTrue("user not persisted for mfa provider", provisioner.activeUserCredentialExists("jabbahut", mfaProvider.getId()));
        assertFalse("user persisted even though we switched mfaProvider", provisioner.activeUserCredentialExists("jabbahut", otherMfaProvider.getId()));
    }

    @Test
    public void testActiveUserCredentialDoesNotExistAcrossProvider() {
        UserGoogleMfaCredentials creds = creds();
        when(jdbcProvisioner.retrieve(anyString(), anyString())).thenThrow(UserMfaConfigDoesNotExistException.class).thenThrow(UserMfaConfigDoesNotExistException.class).thenReturn(creds);

        assertFalse("no user in db but activeCredentialExists returned true", provisioner.activeUserCredentialExists("jabbahut", mfaProvider.getId()));

        provisioner.saveUserCredentials(creds.getUserId(), creds.getSecretKey(), creds.getValidationCode(), creds.getScratchCodes());
        assertFalse("no user in db but activeCredentialExists returned true", provisioner.activeUserCredentialExists("jabbahut", mfaProvider.getId()));

        //provisioner.persistCredentials();
        assertTrue("user not shown as active after persisting", provisioner.activeUserCredentialExists("jabbahut", mfaProvider.getId()));

    }

    @Test(expected = UnsupportedOperationException.class)
    public void testGetSecretKey() {
        provisioner.getSecretKey("jabbahut");
    }


    @Test
    public void isFirstTimeMFAUser() {
        UaaPrincipal uaaPrincipal = mock(UaaPrincipal.class);
        assertTrue(provisioner.isFirstTimeMFAUser(uaaPrincipal));
    }

    @Test
    public void isFirstTimeMFAUser_CredsAreNotInSession() {
        UaaPrincipal uaaPrincipal = mock(UaaPrincipal.class);
        UserGoogleMfaCredentials creds = creds();
        when(jdbcProvisioner.retrieve(any(),any())).thenReturn(creds);
        assertFalse(provisioner.isFirstTimeMFAUser(uaaPrincipal));
    }

    @Test(expected = RuntimeException.class)
    public void isFirstTimeMFAUser_failsIfNotParitallyLoggedIn() {
        provisioner.isFirstTimeMFAUser(null);
    }

    private UserGoogleMfaCredentials creds() {
        UserGoogleMfaCredentials res = new UserGoogleMfaCredentials("jabbahut",
                                                                    "very_sercret_key",
                                                                    74718234,
                                                                    Arrays.asList(1, 22));
        res.setMfaProviderId(mfaProvider.getId());
        return res;
    }

}