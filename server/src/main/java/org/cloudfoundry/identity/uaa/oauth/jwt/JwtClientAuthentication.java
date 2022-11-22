package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.token.Claims;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.springframework.util.MultiValueMap;

import java.time.Instant;
import java.util.Arrays;
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

  public String getClientAssetion(OIDCIdentityProviderDefinition config) {
    String issuer = Optional.ofNullable(config.getJwtclientAuthentication().get("iss")).orElse(config.getRelyingPartyId());
    String audience = Optional.ofNullable(config.getJwtclientAuthentication().get("aud")).orElse(config.getTokenUrl().toString());
    Claims claims = new Claims();
    claims.setAud(Arrays.asList(audience));
    claims.setSub(config.getRelyingPartyId());
    claims.setIss(issuer);
    claims.setJti(UUID.randomUUID().toString().replace("-", ""));
    claims.setIat((int) Instant.now().minusSeconds(120).getEpochSecond());
    claims.setExp(Instant.now().plusSeconds(420).getEpochSecond());
    return JwtHelper.encode(JsonUtils.writeValueAsString(claims), keyInfoService.getActiveKey()).getEncoded();
  }

  public MultiValueMap<String, String> getClientAuthenticationParameters(MultiValueMap<String, String> params, OIDCIdentityProviderDefinition config) {
    if (Objects.isNull(config) || Objects.isNull(config.getJwtclientAuthentication())) {
      return params;
    }
    if (!params.containsKey("client_id")) {
      params.add("client_id", config.getRelyingPartyId());
    }
    params.add("client_assertion_type", GRANT_TYPE);
    params.add("client_assertion", getClientAssetion(config));
    return params;
  }
}
