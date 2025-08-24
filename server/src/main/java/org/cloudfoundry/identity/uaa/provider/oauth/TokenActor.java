
package org.cloudfoundry.identity.uaa.provider.oauth;


import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;

import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.CLIENT_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.ISS;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.SUB;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.USER_NAME;

public class TokenActor {

    private Map<String, Object> claims = new HashMap<>();

	public TokenActor(String subject, String issuer, String clientId, String userName, String userId, String origin) {
		claims.put(SUB, subject);
        claims.put(ISS, issuer);
        claims.put(ClaimConstants.CLIENT_ID, clientId);
        claims.put(ClaimConstants.USER_NAME, userName);
        claims.put(ClaimConstants.USER_ID, userId);
        claims.put(ClaimConstants.ORIGIN, origin);
	}

    public TokenActor(Map<String, Object> existingClaims) {
        if (existingClaims != null) {
            claims.putAll(existingClaims);
        }
    }

	public TokenActor addClaim(String claim, String value) {
        claims.put(claim, value);
        return this;
    }

    public TokenActor addClaim(String claim, String... values) {
        claims.put(claim, values);
        return this;
    }
    public TokenActor removeClaim(String claim) {
        claims.remove(claim);
        return this;
    }

    public Map<String, Object> getClaims() {
        return new HashMap<>(this.claims);
    }

    protected String getStringClaim(String claim) {
        Object value = this.claims.get(claim);
        if (value == null) {
            return null;
        } else if (value instanceof String stringValue) {
            return stringValue;
        } else {
            return value.toString();
        }
    }

    public String getSubject() {
        return getStringClaim(SUB);
    }

    public String getIssuer() {
        return getStringClaim(ISS);
    }

    public String getClientId() {
        return getStringClaim(CLIENT_ID);
    }

    public String getUserName() {
        return getStringClaim(USER_NAME);
    }

    public String getUserId() {
        return getStringClaim(USER_ID);
    }
}
