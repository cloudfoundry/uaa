package org.cloudfoundry.identity.uaa.provider.oauth;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ExternalOAuthLogoutHandlerTest {

  private MockHttpServletRequest request = new MockHttpServletRequest();
  private MockHttpServletResponse response = new MockHttpServletResponse();
  private IdentityProvider identityProvider;
  private OIDCIdentityProviderDefinition oAuthIdentityProviderDefinition;
  private IdentityProviderProvisioning providerProvisioning = mock(IdentityProviderProvisioning.class);
  private OidcMetadataFetcher oidcMetadataFetcher = mock(OidcMetadataFetcher.class);
  private UaaAuthentication uaaAuthentication = mock(UaaAuthentication.class);
  private UaaPrincipal uaaPrincipal = mock(UaaPrincipal.class);
  private IdentityZoneManager identityZoneManager = mock(IdentityZoneManager.class);

  private ExternalOAuthLogoutHandler oAuthLogoutHandler = mock(ExternalOAuthLogoutHandler.class);
  IdentityZoneConfiguration configuration = new IdentityZoneConfiguration();
  IdentityZoneConfiguration original;
  private final String uaa_endsession_url = "http://localhost:8080/uaa/logout.do";


  @BeforeEach
  public void setUp() throws MalformedURLException {
    IdentityZone uaaZone = IdentityZone.getUaa();
    original = IdentityZone.getUaa().getConfig();
    configuration.getLinks().getLogout()
        .setRedirectUrl("/login")
        .setDisableRedirectParameter(true)
        .setRedirectParameterName("redirect");
    uaaZone.setConfig(configuration);
    identityProvider = new IdentityProvider();
    identityProvider.setType(OriginKeys.OIDC10);
    identityProvider.setOriginKey("test");
    identityProvider.setId("id");
    identityProvider.setName("name");
    identityProvider.setActive(true);
    oAuthIdentityProviderDefinition = new OIDCIdentityProviderDefinition();
    oAuthIdentityProviderDefinition.setLogoutUrl(new URL(uaa_endsession_url));
    oAuthIdentityProviderDefinition.setRelyingPartyId("id");
    identityProvider.setConfig(oAuthIdentityProviderDefinition);
    when(providerProvisioning.retrieveByOrigin("test", "uaa")).thenReturn(identityProvider);
    when(uaaAuthentication.getPrincipal()).thenReturn(uaaPrincipal);
    when(uaaAuthentication.getAuthenticationMethods()).thenReturn(Set.of("ext", "oauth"));
    when(uaaPrincipal.getOrigin()).thenReturn("test");
    when(uaaPrincipal.getZoneId()).thenReturn("uaa");
    when(identityZoneManager.getCurrentIdentityZone()).thenReturn(uaaZone);
    oAuthLogoutHandler = new ExternalOAuthLogoutHandler(providerProvisioning, oidcMetadataFetcher, identityZoneManager);
    IdentityZoneHolder.get().setConfig(configuration);
    SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
  }

  @AfterEach
  public void tearDown() {
    IdentityZoneHolder.clear();
    IdentityZone.getUaa().setConfig(original);
    SecurityContextHolder.clearContext();
    request.setQueryString(null);
  }

  @Test
  void determineTargetUrl() {
    request.setQueryString("parameter=value");
    assertEquals("http://localhost:8080/uaa/logout.do?post_logout_redirect_uri=http%3A%2F%2Flocalhost%3Fparameter%3Dvalue&client_id=id",
        oAuthLogoutHandler.determineTargetUrl(request, response, uaaAuthentication));
  }

  @Test
  void determineDefaultTargetUrl() {
    oAuthIdentityProviderDefinition.setLogoutUrl(null);
    IdentityZoneHolder.get().setConfig(null);
    assertEquals("/login",
        oAuthLogoutHandler.determineTargetUrl(request, response, uaaAuthentication));
  }

  @Test
  void constructOAuthProviderLogoutUrl() {
    oAuthLogoutHandler.constructOAuthProviderLogoutUrl(request, "", oAuthIdentityProviderDefinition);
  }

  @Test
  void getLogoutUrl() throws OidcMetadataFetchingException {
    assertEquals(uaa_endsession_url, oAuthLogoutHandler.getLogoutUrl(oAuthIdentityProviderDefinition));
    verify(oidcMetadataFetcher, times(0)).fetchMetadataAndUpdateDefinition(oAuthIdentityProviderDefinition);
  }

  @Test
  void getNewFetchedLogoutUrl() throws OidcMetadataFetchingException {
    oAuthIdentityProviderDefinition.setLogoutUrl(null);
    assertEquals(null, oAuthLogoutHandler.getLogoutUrl(oAuthIdentityProviderDefinition));
    verify(oidcMetadataFetcher, times(1)).fetchMetadataAndUpdateDefinition(oAuthIdentityProviderDefinition);
  }

  @Test
  void getNewInvalidFetchedLogoutUrl() throws OidcMetadataFetchingException {
    oAuthIdentityProviderDefinition.setLogoutUrl(null);
    doThrow(new OidcMetadataFetchingException("")).when(oidcMetadataFetcher).fetchMetadataAndUpdateDefinition(oAuthIdentityProviderDefinition);
    assertEquals(null, oAuthLogoutHandler.getLogoutUrl(oAuthIdentityProviderDefinition));
    verify(oidcMetadataFetcher, times(1)).fetchMetadataAndUpdateDefinition(oAuthIdentityProviderDefinition);
  }

  @Test
  void getOAuthProviderForAuthentication() {
    assertEquals(oAuthIdentityProviderDefinition, oAuthLogoutHandler.getOAuthProviderForAuthentication(uaaAuthentication));
  }

  @Test
  void getNullOAuthProviderForAuthentication() {
    assertEquals(null, oAuthLogoutHandler.getOAuthProviderForAuthentication(null));
  }
}