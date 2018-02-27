package org.cloudfoundry.identity.uaa.oauth.openid;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableList;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ACR;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.AUTH_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EMAIL_VERIFIED;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.EXP;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.FAMILY_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GIVEN_NAME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.IAT;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PHONE_NUMBER;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.PREVIOUS_LOGON_TIME;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ATTRIBUTES;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class IdToken {
    public final String sub;
    public final List<String> aud;
    public final String iss;
    public final Date exp;
    public final Date iat;
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
                   String zid) {
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
    }

    @JsonProperty(ACR)
    public Map<String, Set<String>> getAcr() {
        if (acr == null) {
            return null;
        }
        HashMap<String, Set<String>> acrMap = new HashMap<>();
        acrMap.put("values", acr);
        return acrMap;
    }

    @JsonProperty(EXP)
    public Long getExpInSeconds() {
        return exp.getTime() / 1000;
    }

    @JsonProperty(IAT)
    public Long getIatInSeconds() {
        return iat.getTime() / 1000;
    }

    @JsonProperty(AUTH_TIME)
    public Long getAuthTimeInSeconds() {
        if (authTime == null) {
            return null;
        }
        return authTime.getTime() / 1000;
    }

    @JsonProperty(USER_ID)
    public String userId() {
        return sub;
    }
}
