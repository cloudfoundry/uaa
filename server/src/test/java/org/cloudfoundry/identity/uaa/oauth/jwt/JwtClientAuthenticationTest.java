package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtClientAuthenticationTest {

  private OIDCIdentityProviderDefinition config;
  private KeyInfoService keyInfoService = mock(KeyInfoService.class);
  private JwtClientAuthentication jwtClientAuthentication;

  @BeforeEach
  void setup() throws MalformedURLException {
    jwtClientAuthentication = new JwtClientAuthentication(keyInfoService);
    config = new OIDCIdentityProviderDefinition();
    config.setTokenUrl(new URL("http://localhost:8080/uaa/oauth/token"));
    config.setRelyingPartyId("identity");
    config.setJwtClientAuthentication(true);
    mockKeyInfoService();
  }

  @Test
  void testGetClientAssertion() throws ParseException {
    // When
    String clientAssertion = (String) jwtClientAuthentication.getClientAssertion(config);
    // Then
    validateClientAssertionOidcComplaint(clientAssertion);
  }

  @Test
  void testGetClientAssertionUsingTrueBooleanConfig() throws ParseException {
    // Given
    config.setJwtClientAuthentication(true);
    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    // When
    params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
    // Then
    assertTrue(params.containsKey("client_assertion"));
    assertTrue(params.containsKey("client_assertion_type"));
    validateClientAssertionOidcComplaint((String) params.get("client_assertion").get(0));
  }

  @Test
  void testGetClientAssertionUsingFalseBooleanConfig() throws ParseException {
    // Given
    config.setJwtClientAuthentication(false);
    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    // When
    params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
    // Then
    assertFalse(params.containsKey("client_assertion"));
    assertFalse(params.containsKey("client_assertion_type"));
  }

  @Test
  void testGetClientAssertionUsingCustomConfig() throws ParseException {
    // Given
    HashMap customClaims = new HashMap<>();
    customClaims.put("iss", "identity");
    config.setJwtClientAuthentication(customClaims);
    // When
    String clientAssertion = (String) jwtClientAuthentication.getClientAssertion(config);
    // Then
    validateClientAssertionOidcComplaint(clientAssertion);
  }

  @Test
  void testGetClientAssertionRfc7523Complaint() throws ParseException {
    // Given
    HashMap customClaims = new HashMap<>();
    customClaims.put("iss", "anotherIssuer");
    customClaims.put("aud", "ReceiverEndpoint");
    config.setJwtClientAuthentication(customClaims);
    // When
    String clientAssertion = (String) jwtClientAuthentication.getClientAssertion(config);
    // Then
    validateClientAssertionRfc7523Complaint(clientAssertion, "anotherIssuer", "ReceiverEndpoint");
  }

  @Test
  void testGetClientAuthenticationParameters() throws ParseException {
    // Given
    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    // When
    params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
    // Then
    assertTrue(params.containsKey("client_assertion"));
    assertTrue(params.containsKey("client_assertion_type"));
    assertEquals(Collections.singletonList(JwtClientAuthentication.GRANT_TYPE), params.get("client_assertion_type"));
    assertNotNull(params.get("client_assertion").get(0));
    validateClientAssertionOidcComplaint((String) params.get("client_assertion").get(0));
  }

  @Test
  void testGetClientAuthenticationParametersNullParameter() {
    // When
    assertNull(jwtClientAuthentication.getClientAuthenticationParameters(null, null));
  }

  @Test
  void testGetClientAuthenticationParametersNullJwtClientConfiguration() {
    // Given
    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    config.setJwtClientAuthentication(null);
    // When
    assertEquals(params, jwtClientAuthentication.getClientAuthenticationParameters(params, config));
  }

  private void mockKeyInfoService() {
    KeyInfo keyInfo = mock(KeyInfo.class);
    Signer signer = mock(Signer.class);
    when(keyInfoService.getActiveKey()).thenReturn(keyInfo);
    when(keyInfo.algorithm()).thenReturn("HS256");
    when(keyInfo.getSigner()).thenReturn(signer);
    when(signer.sign(any())).thenReturn("dummy".getBytes());
  }

  private static void validateClientAssertionOidcComplaint(String clientAssertion) throws ParseException {
    JWTClaimsSet jwtClaimsSet = JWTParser.parse(clientAssertion).getJWTClaimsSet();
    assertEquals(Collections.singletonList("http://localhost:8080/uaa/oauth/token"), jwtClaimsSet.getAudience());
    assertEquals("identity", jwtClaimsSet.getSubject());
    assertEquals("identity", jwtClaimsSet.getIssuer());
  }

  private static void validateClientAssertionRfc7523Complaint(String clientAssertion, String iss, String aud) throws ParseException {
    JWTClaimsSet jwtClaimsSet = JWTParser.parse(clientAssertion).getJWTClaimsSet();
    assertEquals(Collections.singletonList(aud), jwtClaimsSet.getAudience());
    assertEquals(iss, jwtClaimsSet.getIssuer());
    assertEquals("identity", jwtClaimsSet.getSubject());
  }
}
