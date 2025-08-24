package org.cloudfoundry.identity.uaa.oauth.openid;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableList;
import org.cloudfoundry.identity.uaa.oauth.AuthTimeDateConverter;
import org.cloudfoundry.identity.uaa.provider.oauth.TokenActor;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ACR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ACT;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUTH_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL_VERIFIED;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXPIRY_IN_SECONDS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.FAMILY_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GIVEN_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.IAT;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PHONE_NUMBER;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PREVIOUS_LOGON_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.REVOCATION_SIGNATURE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class IdToken {
    public static final String ACR_VALUES_KEY = "values";
    public final String sub;
    public final List<String> aud;
    public final String iss;
    public final Date exp;
    public final Date iat;
    @JsonIgnore
    public final Date authTime;
    public final Set<String> amr;
    public final Set<String> acr;
    public final String azp;
    @JsonProperty(GIVEN_NAME)
    public final String givenName;
    @JsonProperty(FAMILY_NAME)
    public final String familyName;
    @JsonProperty(PREVIOUS_LOGON_TIME)
    public final Long previousLogonTime;
    @JsonProperty(PHONE_NUMBER)
    public final String phoneNumber;
    public final Set<String> roles;
    @JsonProperty(USER_ATTRIBUTES)
    public final Map<String, List<String>> userAttributes;
    public final List<String> scope = ImmutableList.of("openid");
    @JsonProperty(EMAIL_VERIFIED)
    public final Boolean emailVerified;
    public final String nonce;
    public final String email;
    @JsonProperty(CID)
    public final String clientId;
    @JsonProperty(GRANT_TYPE)
    public final String grantType;
    @JsonProperty(USER_NAME)
    public final String userName;
    public final String zid;
    public final String origin;
    public final String jti;
    @JsonProperty(REVOCATION_SIGNATURE)
    public final String revSig;
    private Map<String,Object> tokenActor;

    public IdToken(String sub,
            List<String> aud,
            String iss,
            Date exp,
            Date iat,
            Date authTime,
            Set<String> amr,
            Set<String> acr,
            String azp,
            String givenName,
            String familyName,
            Long previousLogonTime,
            String phoneNumber,
            Set<String> roles,
            Map<String, List<String>> userAttributes,
            Boolean emailVerified,
            String nonce,
            String email,
            String clientId,
            String grantType,
            String userName,
            String zid,
            String origin,
            String jti,
            String revSig) {
        this.sub = sub;
        this.aud = aud;
        this.iss = iss;
        this.exp = exp;
        this.iat = iat;
        this.authTime = authTime;
        this.amr = amr;
        this.acr = acr;
        this.azp = azp;
        this.givenName = givenName;
        this.familyName = familyName;
        this.previousLogonTime = previousLogonTime;
        this.phoneNumber = phoneNumber;
        this.roles = roles;
        this.userAttributes = userAttributes;
        this.emailVerified = emailVerified;
        this.nonce = nonce;
        this.email = email;
        this.clientId = clientId;
        this.grantType = grantType;
        this.userName = userName;
        this.zid = zid;
        this.origin = origin;
        this.jti = jti;
        this.revSig = revSig;
    }

    @JsonProperty(ACR)
    public Map<String, Set<String>> getAcr() {
        if (acr == null) {
            return null;
        }
        HashMap<String, Set<String>> acrMap = new HashMap<>();
        acrMap.put(ACR_VALUES_KEY, acr);
        return acrMap;
    }

    @JsonProperty(CLIENT_ID)
    public String getClientId() {
        return clientId;
    }

    @JsonProperty(EXPIRY_IN_SECONDS)
    public Long getExpInSeconds() {
        return exp.getTime() / 1000;
    }

    @JsonProperty(IAT)
    public Long getIatInSeconds() {
        return iat.getTime() / 1000;
    }

    @JsonProperty(AUTH_TIME)
    public Long getAuthTimeInSeconds() {
        return AuthTimeDateConverter.dateToAuthTime(authTime);
    }

    @JsonProperty(USER_ID)
    public String userId() {
        return sub;
    }

    @JsonProperty(ACT)
    public Map<String, Object> getTokenActor() {
        return this.tokenActor;
    }

    public void setTokenActor(Map<String, Object> tokenActor) {
        this.tokenActor = tokenActor;
    }

    public void setTokenActor(TokenActor tokenActor) {
        this.tokenActor = tokenActor == null ? null : tokenActor.getClaims();
    }

    @JsonIgnore
    public Map<String, Object> getClaimMap() {
        return JsonUtils.convertValue(this, HashMap.class);
    }
}
