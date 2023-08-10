package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.util.MultiValueMap;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public class JwtClientAuthentication {

  public static final String GRANT_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

  private final KeyInfoService keyInfoService;

  public JwtClientAuthentication(
      KeyInfoService keyInfoService) {
    this.keyInfoService = keyInfoService;
  }

  public String getClientAssertion(OIDCIdentityProviderDefinition config) {
    HashMap<String, String> jwtClientConfiguration = Optional.ofNullable(getJwtClientConfigurationElements(config.getJwtClientAuthentication())).orElse(new HashMap<>());
    String issuer = Optional.ofNullable(jwtClientConfiguration.get("iss")).orElse(config.getRelyingPartyId());
    String audience = Optional.ofNullable(jwtClientConfiguration.get("aud")).orElse(config.getTokenUrl().toString());
    String kid = Optional.ofNullable(jwtClientConfiguration.get("kid")).orElse(keyInfoService.getActiveKey().keyId());
    Claims claims = new Claims();
    claims.setAud(Arrays.asList(audience));
    claims.setSub(config.getRelyingPartyId());
    claims.setIss(issuer);
    claims.setJti(UUID.randomUUID().toString().replace("-", ""));
    claims.setIat((int) Instant.now().minusSeconds(120).getEpochSecond());
    claims.setExp(Instant.now().plusSeconds(300).getEpochSecond());
    KeyInfo signingKeyInfo = Optional.ofNullable(keyInfoService.getKey(kid)).orElseThrow(() -> new BadCredentialsException("Missing requested signing key"));
    return signingKeyInfo.verifierCertificate().isPresent() ?
        JwtHelper.encodePlusX5t(JsonUtils.writeValueAsString(claims), signingKeyInfo, signingKeyInfo.verifierCertificate().orElseThrow()).getEncoded() :
        JwtHelper.encode(JsonUtils.writeValueAsString(claims), signingKeyInfo).getEncoded();
  }

  public MultiValueMap<String, String> getClientAuthenticationParameters(MultiValueMap<String, String> params, OIDCIdentityProviderDefinition config) {
    if (Objects.isNull(config) || Objects.isNull(getJwtClientConfigurationElements(config.getJwtClientAuthentication()))) {
      return params;
    }
    if (!params.containsKey("client_id")) {
      params.add("client_id", config.getRelyingPartyId());
    }
    params.add("client_assertion_type", GRANT_TYPE);
    params.add("client_assertion", getClientAssertion(config));
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
}
