package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtClientAuthenticationTest {

  private static final String KEY_ID = "tokenKeyId";
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
    mockKeyInfoService(null, JwtHelperX5tTest.CERTIFICATE_1);
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
    String clientAssertion = (String) params.get("client_assertion").get(0);
    validateClientAssertionOidcComplaint(clientAssertion);
    JWSHeader header = getJwtHeader(clientAssertion);
    assertEquals(KEY_ID, header.getKeyID());
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

  @Test
  void testGetClientAssertionUnknownSingingKey() throws ParseException {
    // Given
    HashMap customClaims = new HashMap<>();
    customClaims.put("kid", "wrong-key-id");
    config.setJwtClientAuthentication(customClaims);
    // When
    assertThrowsExactly(BadCredentialsException.class, () -> jwtClientAuthentication.getClientAssertion(config));
  }

  @Test
  void testGetClientAssertionCustomSingingKey() throws ParseException {
    // Given
    mockKeyInfoService("myKey", JwtHelperX5tTest.CERTIFICATE_1);
    HashMap customClaims = new HashMap<>();
    customClaims.put("kid", "myKey");
    config.setJwtClientAuthentication(customClaims);
    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    // When
    params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
    // Then
    assertTrue(params.containsKey("client_assertion"));
    assertTrue(params.containsKey("client_assertion_type"));
    String clientAssertion = (String) params.get("client_assertion").get(0);
    validateClientAssertionOidcComplaint(clientAssertion);
    JWSHeader header = getJwtHeader(clientAssertion);
    assertEquals("myKey", header.getKeyID());
    assertNull(header.getJWKURL());
  }

  @Test
  void testGetClientAssertionCustomSingingKeyButNoCertificate() throws ParseException {
    // Given
    mockKeyInfoService("myKey", null);
    HashMap customClaims = new HashMap<>();
    customClaims.put("kid", "myKey");
    config.setJwtClientAuthentication(customClaims);
    MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
    // When
    params = jwtClientAuthentication.getClientAuthenticationParameters(params, config);
    // Then
    assertTrue(params.containsKey("client_assertion"));
    assertTrue(params.containsKey("client_assertion_type"));
    String clientAssertion = (String) params.get("client_assertion").get(0);
    validateClientAssertionOidcComplaint(clientAssertion);
    JWSHeader header = getJwtHeader(clientAssertion);
    assertEquals("myKey", header.getKeyID());
    assertNotNull(header.getJWKURL());
    assertEquals("http://localhost:8080/uaa/token_key", header.getJWKURL().toString());
  }

  private void mockKeyInfoService(String keyId, String x509Certificate) {
    KeyInfo keyInfo = mock(KeyInfo.class);
    Signer signer = mock(Signer.class);
    if (keyId != null) {
      KeyInfo customKeyInfo = mock(KeyInfo.class);
      when(customKeyInfo.keyId()).thenReturn(keyId);
      when(keyInfoService.getKey(keyId)).thenReturn(customKeyInfo);
      when(customKeyInfo.algorithm()).thenReturn("RS256");
      when(customKeyInfo.keyURL()).thenReturn("http://localhost:8080/uaa/token_key");
      when(customKeyInfo.getSigner()).thenReturn(signer);
      when(customKeyInfo.verifierCertificate()).thenReturn(x509Certificate != null ? Optional.of(x509Certificate): Optional.empty());
    }
    when(keyInfo.keyId()).thenReturn(KEY_ID);
    when(keyInfoService.getKey(KEY_ID)).thenReturn(keyInfo);
    when(keyInfoService.getActiveKey()).thenReturn(keyInfo);
    when(keyInfo.algorithm()).thenReturn("RS256");
    when(keyInfo.keyURL()).thenReturn("http://localhost:8080/uaa/token_key");
    when(keyInfo.getSigner()).thenReturn(signer);
    when(keyInfo.verifierCertificate()).thenReturn(x509Certificate != null ? Optional.of(x509Certificate): Optional.of(JwtHelperX5tTest.CERTIFICATE_1));
    when(signer.sign(any())).thenReturn("dummy".getBytes());
  }

  private static JWSHeader getJwtHeader(String jwtString) throws ParseException {
    JWT jwt = JWTParser.parse(jwtString);
    return (JWSHeader) jwt.getHeader();
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
