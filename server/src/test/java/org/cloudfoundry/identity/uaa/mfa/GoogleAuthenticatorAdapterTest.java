package org.cloudfoundry.identity.uaa.mfa;

import com.google.zxing.WriterException;
import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class GoogleAuthenticatorAdapterTest {

    GoogleAuthenticatorAdapter adapter;
    MfaCredentialsSessionCache credCache;
    GoogleAuthenticator authenticator;
    GoogleAuthenticatorKey authenticatorKey;
    UserGoogleMfaCredentials userGoogleMfaCredentials;

    String SECRET_KEY = "secret";

    @Before
    public void setup() {
        adapter = new GoogleAuthenticatorAdapter();
        credCache = mock(MfaCredentialsSessionCache.class);
        adapter.setCredCache(credCache);

        authenticator = mock(GoogleAuthenticator.class);
        authenticatorKey = mock(GoogleAuthenticatorKey.class);
        when(authenticatorKey.getKey()).thenReturn(SECRET_KEY);
        adapter.setAuthenticator(authenticator);

        userGoogleMfaCredentials = mock(UserGoogleMfaCredentials.class);
        when(userGoogleMfaCredentials.getSecretKey()).thenReturn(SECRET_KEY);
    }

    @Test
    public void testGetUrl_WhenCached() throws IOException, WriterException {
        when(credCache.getCredentials()).thenReturn(userGoogleMfaCredentials);
        String otpAuthURL = adapter.getOtpAuthURL("issuer", "userid", "username");

        Assert.assertNotNull(otpAuthURL);
        verify(authenticator, never()).createCredentials(anyString());
    }

    @Test
    public void testGetUrl_WhenNotCached() throws IOException, WriterException {
        when(authenticator.createCredentials(anyString())).thenReturn(authenticatorKey);
        String otpAuthURL = adapter.getOtpAuthURL("issuer", "userid", "username");

        Assert.assertNotNull(otpAuthURL);
    }

    @Test
    public void testAuthUrlIsNotChanging() throws IOException, WriterException {
        when(authenticator.createCredentials("userid")).thenReturn(authenticatorKey);
        String otpAuthURL = adapter.getOtpAuthURL("issuer", "userid", "username");

        when(credCache.getCredentials()).thenReturn(userGoogleMfaCredentials);
        Assert.assertEquals(otpAuthURL, adapter.getOtpAuthURL("issuer","userid", "username"));
    }

    @Test
    public void testGetOtpSecret_WhenCached() throws IOException, WriterException {
        when(credCache.getCredentials()).thenReturn(userGoogleMfaCredentials);
        String otpSecret = adapter.getOtpSecret("userid");

        Assert.assertEquals(SECRET_KEY, otpSecret);
        verify(authenticator, never()).createCredentials(anyString());
    }

    @Test
    public void testGetOtpSecret_WhenNotCached() throws IOException, WriterException {
        when(authenticator.createCredentials(anyString())).thenReturn(authenticatorKey);
        String otpSecret = adapter.getOtpSecret("userid");

        Assert.assertEquals(SECRET_KEY, otpSecret);

    }

    @Test
    public void testOtpSecretIsNotChanging() throws IOException, WriterException {
        when(authenticator.createCredentials("userid")).thenReturn(authenticatorKey);
        String otpAuthURL = adapter.getOtpSecret("userid");

        when(credCache.getCredentials()).thenReturn(userGoogleMfaCredentials);
        Assert.assertEquals(otpAuthURL, adapter.getOtpSecret("userid"));
    }
}