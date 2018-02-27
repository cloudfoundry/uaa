package org.cloudfoundry.identity.uaa.oauth.openid;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.collect.ImmutableList;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
    @JsonProperty("given_name")
    public final String givenName;
    @JsonProperty("family_name")
    public final String familyName;
    @JsonProperty("previous_logon_time")
    public final Long previousLogonTime;
    @JsonProperty("phone_number")
    public final String phoneNumber;
    public final Set<String> roles;
    @JsonProperty("user_attributes")
    public final Map<String, List<String>> userAttributes;
    public final List<String> scope = ImmutableList.of("openid");
    @JsonProperty("email_verified")
    public final Boolean emailVerified;
    public final String nonce;
    public final String email;
    @JsonProperty("cid")
    public final String clientId;
    @JsonProperty("grant_type")
    public final String grantType;

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
                   String grantType) {
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
    }

    @JsonProperty("acr")
    public Map<String, Set<String>> getAcr() {
        if (acr == null) {
            return null;
        }
        HashMap<String, Set<String>> acrMap = new HashMap<>();
        acrMap.put("values", acr);
        return acrMap;
    }

    @JsonProperty("exp")
    public Long getExpInSeconds() {
        return exp.getTime() / 1000;
    }

    @JsonProperty("iat")
    public Long getIatInSeconds() {
        return iat.getTime() / 1000;
    }

    @JsonProperty("auth_time")
    public Long getAuthTimeInSeconds() {
        if (authTime == null) {
            return null;
        }
        return authTime.getTime() / 1000;
    }

    @JsonProperty("user_id")
    public String userId() {
        return sub;
    }
}
