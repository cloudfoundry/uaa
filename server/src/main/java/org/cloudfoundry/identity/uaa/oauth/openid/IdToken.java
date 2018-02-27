package org.cloudfoundry.identity.uaa.oauth.openid;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class IdToken {
    public final String sub;
    public final String aud;
    public final String iss;
    public final Date exp;
    public final Date iat;
    @JsonProperty("auth_time")
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
    public final String scope = "openid";

    public IdToken(String sub,
                   String aud,
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
                   Map<String, List<String>> userAttributes) {
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
    }

    @JsonProperty("acr")
    public Map<String, Set<String>> getAcr() {
        HashMap<String, Set<String>> acrMap = new HashMap<>();
        acrMap.put("values", acr);
        return acrMap;
    }

}
