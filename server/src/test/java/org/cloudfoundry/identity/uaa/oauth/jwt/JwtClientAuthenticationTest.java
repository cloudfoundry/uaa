package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetchingException;
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
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtClientAuthenticationTest {

  private static final String KEY_ID = "tokenKeyId";
  private static final String INVALID_CLIENT_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJjYmEyZmRlN2ZkYTg0YzMzYTdkZDQ5MWVmMzljZWY5NiIsImF1ZCI6WyJodHRwOi8vbG9jYWxob3N0OjgwODAvdWFhL29hdXRoL3Rva2VuIl0sInN1YiI6ImlkZW50aXR5IiwiaXNzIjoic29tZVRoaW5nIn0.HLXpsPJw0SvF8DcGmmifzJJLxX4hmfwILAtAFedk48c";
  private static final String INVALID_CLIENT_ALG = "eyJhbGciOiJIUzI1NiIsImtpZCI6InRva2VuS2V5SWQiLCJ0eXAiOiJKV1QifQ.eyJleHAiOjE2OTU4NDEyMDYsImp0aSI6ImRhMzdjYzFjMjkzOTQzMWE4YjUzZTI5MmZiMjYxMDZhIiwiYXVkIjpbImh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC91YWEvb2F1dGgvdG9rZW4iXSwic3ViIjoiaWRlbnRpdHkiLCJpc3MiOiJpZGVudGl0eSIsImlhdCI6MTY5NTg0MDc4NiwicmV2b2NhYmxlIjpmYWxzZX0.gFYuUjzupzeKNK2Uq3Ijp0rDIcJfI80wl3Pt5MSypPM";
  private OIDCIdentityProviderDefinition config;
  private KeyInfoService keyInfoService = mock(KeyInfoService.class);
  private OidcMetadataFetcher oidcMetadataFetcher = mock(OidcMetadataFetcher.class);
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

  @Test
  void testGetClientIdOfClientAssertion() throws ParseException {
    // When
    String clientAssertion = (String) jwtClientAuthentication.getClientAssertion(config);
    // Then
    assertEquals("identity", jwtClientAuthentication.getClientId(clientAssertion));
  }

  @Test
  void testRequestInvalidateClientAssertion() throws Exception {
    // Then
    assertFalse(jwtClientAuthentication.validateClientJwt(getMockedRequestParameter("test", INVALID_CLIENT_JWT), getMockedClientJwtConfiguration(null), "identity"));
  }

  @Test
  void testWrongAssertionInvalidateClientId() {
    // Given
    jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher);
    // Then
    Exception exception = assertThrows(BadCredentialsException.class, () ->
        jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null,  jwtClientAuthentication.getClientAssertion(config)),
            // pass a different client_id to the provided one from client_assertion JWT
            getMockedClientJwtConfiguration(null), "wrong_client_id"));
    assertEquals("Wrong client_assertion", exception.getMessage());
  }

  @Test
  void testBadAlgorithmInvalidateClientId() throws Exception {
    // Given
    jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher);
    ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration(null);
    when(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration)).thenReturn(clientJwtConfiguration.getJwkSet());
    // Then
    Exception exception = assertThrows(BadCredentialsException.class, () ->
        jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, INVALID_CLIENT_ALG),
            clientJwtConfiguration, "identity"));
    assertEquals("Bad client_assertion algorithm", exception.getMessage());
  }

  @Test
  void testOidcFetchFailed() throws Exception {
    // Given
    jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher);
    ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration(null);
    when(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration)).thenThrow(new OidcMetadataFetchingException(""));
    // Then
    Exception exception = assertThrows(BadCredentialsException.class, () ->
        jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, jwtClientAuthentication.getClientAssertion(config)),
            clientJwtConfiguration, "identity"));
    assertEquals("Bad client_assertion", exception.getMessage());
  }

  @Test
  void testUntrustedClientAssertion() throws Exception {
    // Given
    jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher);
    // create client assertion with key ids which wont map to provide JWT, lead to failing validateClientJWToken check
    ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration("extId");
    when(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration)).thenReturn(clientJwtConfiguration.getJwkSet());
    String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
    // When
    Exception exception = assertThrows(BadCredentialsException.class, () ->
        jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, clientAssertion), clientJwtConfiguration, "identity"));
    // Then, expect key resolution error because of not maching configured keys to JWT kid
    assertEquals("Untrusted client_assertion", exception.getMessage());
  }

  @Test
  void testSignatureInvalidateClientAssertion() throws Exception {
    // Given
    jwtClientAuthentication = new JwtClientAuthentication(keyInfoService, oidcMetadataFetcher);
    ClientJwtConfiguration clientJwtConfiguration = getMockedClientJwtConfiguration(null);
    when(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration)).thenReturn(clientJwtConfiguration.getJwkSet());
    String clientAssertion = jwtClientAuthentication.getClientAssertion(config);
    // When
    Exception exception = assertThrows(BadCredentialsException.class, () ->
        jwtClientAuthentication.validateClientJwt(getMockedRequestParameter(null, clientAssertion), clientJwtConfiguration, "identity"));
    // Then, expect signature failed because mockKeyInfoService creates corrupted signature
    assertEquals("Unauthorized client_assertion", exception.getMessage());
  }

  @Test
  void testGetClientIdOfInvalidClientAssertion() throws ParseException {
    // Then
    assertThrows(BadCredentialsException.class, () -> jwtClientAuthentication.getClientId(INVALID_CLIENT_JWT));
    assertThrows(BadCredentialsException.class, () -> jwtClientAuthentication.getClientId("eyXXX"));
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
      when(customKeyInfo.verifierCertificate()).thenReturn(x509Certificate != null ? Optional.of(X509CertUtils.parse(x509Certificate)): Optional.empty());
    }
    when(keyInfo.keyId()).thenReturn(KEY_ID);
    when(keyInfoService.getKey(KEY_ID)).thenReturn(keyInfo);
    when(keyInfoService.getActiveKey()).thenReturn(keyInfo);
    when(keyInfo.algorithm()).thenReturn("RS256");
    when(keyInfo.keyURL()).thenReturn("http://localhost:8080/uaa/token_key");
    when(keyInfo.getSigner()).thenReturn(signer);
    when(keyInfo.verifierCertificate()).thenReturn(x509Certificate != null ? Optional.of(X509CertUtils.parse(x509Certificate)): Optional.of(X509CertUtils.parse(JwtHelperX5tTest.CERTIFICATE_1)));
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

  private static Map<String, String[]> getMockedRequestParameter(String type, String assertion) {
    Map<String, String[]> requestParameters = new HashMap<>();
    if (type != null) {
      requestParameters.put(JwtClientAuthentication.CLIENT_ASSERTION_TYPE, new String[] { type });
    } else {
      requestParameters.put(JwtClientAuthentication.CLIENT_ASSERTION_TYPE, new String[] { JwtClientAuthentication.GRANT_TYPE });
    }
    requestParameters.put(JwtClientAuthentication.CLIENT_ASSERTION, new String[] { assertion} );
    return requestParameters;
  }

  private static ClientJwtConfiguration getMockedClientJwtConfiguration(String keyId) throws ParseException {
    KeyInfo keyInfo = KeyInfoBuilder.build(keyId != null ? keyId : "tokenKeyId", JwtHelperX5tTest.SIGNING_KEY_1, "http://localhost:8080/uaa");
    return ClientJwtConfiguration.parse(JWK.parse(keyInfo.getJwkMap()).toString());
  }

}
