package org.cloudfoundry.identity.uaa.spiffe;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.oauth.TokenEndpointBuilder;
import org.cloudfoundry.identity.uaa.oauth.jwt.JwtHelper;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUD;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXPIRY_IN_SECONDS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.IAT;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.JTI;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;

/** Builds and signs a JWT-SVID with UAA's active token-signing key. */
@Component
@ConditionalOnProperty(prefix = "uaa.spiffe", name = "instance-identity-ca")
public class JwtSvidSigner {

    private final KeyInfoService keyInfoService;
    private final TokenEndpointBuilder tokenEndpointBuilder;
    private final SpiffeProperties properties;

    public JwtSvidSigner(KeyInfoService keyInfoService,
                         TokenEndpointBuilder tokenEndpointBuilder,
                         SpiffeProperties properties) {
        this.keyInfoService = keyInfoService;
        this.tokenEndpointBuilder = tokenEndpointBuilder;
        this.properties = properties;
    }

    public record JwtSvidResult(String svid, String spiffeId, long expiresAt) {
    }

    public JwtSvidResult sign(String spiffeId, CfInstanceIdentity identity, String processType, String audience) {
        long iat = Instant.now().getEpochSecond();
        long exp = iat + properties.jwtSvidTtlSeconds();

        Map<String, Object> cf = new LinkedHashMap<>();
        cf.put("org_id", identity.orgId());
        cf.put("space_id", identity.spaceId());
        cf.put("app_id", identity.appId());
        cf.put("process_type", processType);

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put(ISS, tokenEndpointBuilder.getTokenEndpoint(IdentityZoneHolder.get()));
        claims.put(SUB, spiffeId);
        claims.put(AUD, List.of(audience));
        claims.put(IAT, iat);
        claims.put(EXPIRY_IN_SECONDS, exp);
        claims.put(JTI, UUID.randomUUID().toString());
        claims.put("cf", cf);

        KeyInfo activeKey = keyInfoService.getActiveKey();
        String svid = JwtHelper.encode(claims, activeKey).getEncoded();
        return new JwtSvidResult(svid, spiffeId, exp);
    }
}
