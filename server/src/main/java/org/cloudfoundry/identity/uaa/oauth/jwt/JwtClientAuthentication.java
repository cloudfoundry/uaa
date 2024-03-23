package org.cloudfoundry.identity.uaa.oauth.jwt;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.cloudfoundry.identity.uaa.client.ClientJwtConfiguration;
import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.beans.ApplicationContextProvider;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetcher;
import org.cloudfoundry.identity.uaa.provider.oauth.OidcMetadataFetchingException;
import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManagerImpl;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.MultiValueMap;

import java.net.URISyntaxException;
import java.text.ParseException;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.util.UaaStringUtils.isNotEmpty;

public class JwtClientAuthentication {

  public static final String GRANT_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
  public static final String CLIENT_ASSERTION = "client_assertion";
  public static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";
  private static final Pattern DYNAMIC_VALUE_PARAMETER_PATTERN = Pattern.compile("^\\$\\{(?<name>[\\w.\\-]++)(:++(?<default>[\\w:./=+\\-]++)*+)?}$");

  // no signature check with invalid algorithms
  private static final Set<Algorithm> NOT_SUPPORTED_ALGORITHMS = Set.of(Algorithm.NONE, JWSAlgorithm.HS256, JWSAlgorithm.HS384, JWSAlgorithm.HS512);
  private static final Set<String> JWT_REQUIRED_CLAIMS = Set.of(ClaimConstants.ISS, ClaimConstants.SUB, ClaimConstants.AUD,
      ClaimConstants.EXPIRY_IN_SECONDS, ClaimConstants.JTI);

  private final KeyInfoService keyInfoService;
  private final OidcMetadataFetcher oidcMetadataFetcher;

  public JwtClientAuthentication(
      KeyInfoService keyInfoService) {
    this(keyInfoService, null);
  }

  public JwtClientAuthentication(KeyInfoService keyInfoService, OidcMetadataFetcher oidcMetadataFetcher) {
    this.keyInfoService = keyInfoService;
    this.oidcMetadataFetcher = oidcMetadataFetcher;
  }

  public String getClientAssertion(OIDCIdentityProviderDefinition config) {
    HashMap<String, String> jwtClientConfiguration = Optional.ofNullable(getJwtClientConfigurationElements(config.getJwtClientAuthentication())).orElse(new HashMap<>());
    String issuer = readJwtClientOption(jwtClientConfiguration.get("iss"), config.getRelyingPartyId());
    String audience = readJwtClientOption(jwtClientConfiguration.get("aud"), config.getTokenUrl().toString());
    String kid = readJwtClientOption(jwtClientConfiguration.get("kid"), keyInfoService.getActiveKey().keyId());
    Claims claims = new Claims();
    claims.setAud(Arrays.asList(audience));
    claims.setSub(config.getRelyingPartyId());
    claims.setIss(issuer);
    claims.setJti(UUID.randomUUID().toString().replace("-", ""));
    claims.setIat((int) Instant.now().minusSeconds(120).getEpochSecond());
    claims.setExp(Instant.now().plusSeconds(300).getEpochSecond());
    KeyInfo signingKeyInfo = loadKeyInfo(keyInfoService, jwtClientConfiguration, kid);
    return signingKeyInfo.verifierCertificate().isPresent() ?
        JwtHelper.encodePlusX5t(claims.getClaimMap(), signingKeyInfo, signingKeyInfo.verifierCertificate().orElseThrow()).getEncoded() :
        JwtHelper.encode(claims.getClaimMap(), signingKeyInfo).getEncoded();
  }

  public MultiValueMap<String, String> getClientAuthenticationParameters(MultiValueMap<String, String> params, OIDCIdentityProviderDefinition config) {
    if (Objects.isNull(config) || Objects.isNull(getJwtClientConfigurationElements(config.getJwtClientAuthentication()))) {
      return params;
    }
    if (!params.containsKey("client_id")) {
      params.add("client_id", config.getRelyingPartyId());
    }
    params.add(CLIENT_ASSERTION_TYPE, GRANT_TYPE);
    params.add(CLIENT_ASSERTION, getClientAssertion(config));
    return params;
  }

  private static HashMap<String, String> getJwtClientConfigurationElements(Object jwtClientAuthentication) {
    HashMap<String, String> jwtClientConfiguration = null;
    if (jwtClientAuthentication instanceof Boolean && ((boolean) jwtClientAuthentication)) {
      jwtClientConfiguration = new HashMap<>();
    } else if (jwtClientAuthentication instanceof HashMap) {
      jwtClientConfiguration = (HashMap<String, String>) jwtClientAuthentication;
    }
    return jwtClientConfiguration;
  }

  public boolean validateClientJwt(Map<String, String[]> requestParameters, ClientJwtConfiguration clientJwtConfiguration, String clientId) {
    if (GRANT_TYPE.equals(UaaStringUtils.getSafeParameterValue(requestParameters.get(CLIENT_ASSERTION_TYPE)))) {
      try {
        String clientAssertion = UaaStringUtils.getSafeParameterValue(requestParameters.get(CLIENT_ASSERTION));
        if (!clientId.equals(getClientId(clientAssertion))) {
          throw new BadCredentialsException("Wrong client_assertion");
        }
        return clientId.equals(validateClientJWToken(JWTParser.parse(clientAssertion), oidcMetadataFetcher == null ? new JWKSet() :
            JWKSet.parse(oidcMetadataFetcher.fetchWebKeySet(clientJwtConfiguration).getKeySetMap()),
            clientId, keyInfoService.getTokenEndpointUrl()).getSubject());
      } catch (ParseException | URISyntaxException | OidcMetadataFetchingException e) {
        throw new BadCredentialsException("Bad client_assertion", e);
      }
    }
    return false;
  }

  public static String getClientId(String clientAssertion) {
    try {
      JWTClaimsSet clientToken = clientAssertion != null ? JWTParser.parse(clientAssertion).getJWTClaimsSet() : null;
      if (clientToken != null && clientToken.getSubject() != null && clientToken.getIssuer() != null &&
          clientToken.getSubject().equals(clientToken.getIssuer()) && clientToken.getAudience() != null && clientToken.getJWTID() != null &&
          clientToken.getExpirationTime() != null) {
        // required claims, e.g. https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
        return clientToken.getSubject();
      }
      throw new BadCredentialsException("Bad credentials");
    } catch (ParseException e) {
      throw new BadCredentialsException("Bad client_assertion", e);
    }
  }

  private JWTClaimsSet validateClientJWToken(JWT jwtAssertion, JWKSet jwkSet, String expectedClientId, String expectedAud) {
    Algorithm algorithm = jwtAssertion.getHeader().getAlgorithm();
    if (algorithm == null || NOT_SUPPORTED_ALGORITHMS.contains(algorithm) || !(algorithm instanceof JWSAlgorithm)) {
      throw new BadCredentialsException("Bad client_assertion algorithm");
    }
    JWKSource<SecurityContext> keySource = new ImmutableJWKSet<>(jwkSet);
    JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>((JWSAlgorithm) algorithm, keySource);
    ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
    jwtProcessor.setJWSKeySelector(keySelector);

    JWTClaimsSet.Builder claimSetBuilder = new JWTClaimsSet.Builder().issuer(expectedClientId).subject(expectedClientId);
    jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(expectedAud, claimSetBuilder.build(), JWT_REQUIRED_CLAIMS));

    try {
      return jwtProcessor.process(jwtAssertion, null);
    } catch (BadJWSException | BadJWTException jwtException) { // signature failed
      throw new BadCredentialsException("Unauthorized client_assertion", jwtException);
    } catch (BadJOSEException | JOSEException e) { // key resolution, structure of JWT failed
      throw new BadCredentialsException("Untrusted client_assertion", e);
    }
  }

  private static KeyInfo loadKeyInfo(KeyInfoService keyInfoService, HashMap<String, String> jwtClientConfiguration, String kid) {
    KeyInfo keyInfo;
    String signingKey = readJwtClientOption(jwtClientConfiguration.get("key"), null);
    if (signingKey == null) {
      keyInfo = Optional.ofNullable(keyInfoService.getKey(kid)).orElseThrow(() -> new BadCredentialsException("Missing requested signing key"));
    } else {
      String signingAlg = readJwtClientOption(jwtClientConfiguration.get("alg"), JWSAlgorithm.RS256.getName());
      String signingCert = readJwtClientOption(jwtClientConfiguration.get("cert"), null);
      keyInfo = KeyInfoBuilder.build(kid, signingKey, UaaStringUtils.DEFAULT_UAA_URL, signingAlg, signingCert);
    }
    return keyInfo;
  }

  private static String readJwtClientOption(String jwtClientOption, String defaultOption) {
    String value;
    if (isNotEmpty(jwtClientOption)) {
      // check if dynamic value means, a reference to another section in uaa yaml is defined
      Matcher matcher = getDynamicValueMatcher(jwtClientOption);
      if (matcher.find()) {
        value = Optional.ofNullable(getDynamicValue(matcher)).orElse(getDefaultValue(matcher));
      } else {
        value = jwtClientOption;
      }
    } else {
      value = defaultOption;
    }
    return value;
  }

  private static Matcher getDynamicValueMatcher(String value) {
    return DYNAMIC_VALUE_PARAMETER_PATTERN.matcher(value);
  }

  private static String getDynamicValue(Matcher m) {
    /* return a reference from application environment only if in default zone */
    if (!(new IdentityZoneManagerImpl().isCurrentZoneUaa())) {
      return null;
    }
    ApplicationContext applicationContext = ApplicationContextProvider.getApplicationContext();
    return applicationContext != null ? applicationContext.getEnvironment().getProperty(m.group("name")) : null;
  }

  private static String getDefaultValue(Matcher m) {
    return m.group("default");
  }
}
