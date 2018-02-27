package org.cloudfoundry.identity.uaa.oauth.openid;

import org.springframework.util.MultiValueMap;

import java.util.Date;
import java.util.Set;

public class IdToken {
    public final String sub;
    public final String aud;
    public final String iss;
    public final Date exp;
    public final Date iat;
    public final Date authTime;
    public final Set<String> amr;
    public final Set<String> acr;
    public final String azp;
    public final String givenName;
    public final String familyName;
    public final Long previousLogonTime;
    public final String phoneNumber;
    public final Set<String> roles;
    public final MultiValueMap<String, String> userAttributes;
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
                   MultiValueMap<String, String> userAttributes) {
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
}
