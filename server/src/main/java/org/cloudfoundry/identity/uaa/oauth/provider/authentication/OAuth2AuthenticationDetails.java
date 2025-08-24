package org.cloudfoundry.identity.uaa.oauth.provider.authentication;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import java.io.Serial;
import java.io.Serializable;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 server
 */
public class OAuth2AuthenticationDetails implements Serializable {

    @Serial
    private static final long serialVersionUID = -2981260975134202737L;

    public static final String ACCESS_TOKEN_VALUE = OAuth2AuthenticationDetails.class.getSimpleName() + ".ACCESS_TOKEN_VALUE";

    public static final String ACCESS_TOKEN_TYPE = OAuth2AuthenticationDetails.class.getSimpleName() + ".ACCESS_TOKEN_TYPE";

    private final String remoteAddress;

    private final String sessionId;

    private final String tokenValue;

    private final String tokenType;

    private final String display;

    private transient Object decodedDetails;


    /**
     * Records the access token value and remote address and will also set the session Id if a session already exists
     * (it won't create one).
     * 
     * @param request that the authentication request was received from
     */
    public OAuth2AuthenticationDetails(HttpServletRequest request) {
        this.tokenValue = (String) request.getAttribute(ACCESS_TOKEN_VALUE);
        this.tokenType = (String) request.getAttribute(ACCESS_TOKEN_TYPE);
        this.remoteAddress = request.getRemoteAddr();

        HttpSession session = request.getSession(false);
        this.sessionId = session != null ? session.getId() : null;
        StringBuilder builder = new StringBuilder();
        if (remoteAddress != null) {
            builder.append("remoteAddress=").append(remoteAddress);
        }
        if (sessionId != null) {
            if (builder.length() > 1) {
                builder.append(", ");
            }
            builder.append("sessionId=<SESSION>");
        }
        if (tokenType != null) {
            if (builder.length() > 1) {
                builder.append(", ");
            }
            builder.append("tokenType=").append(this.tokenType);
        }
        if (tokenValue != null) {
            if (builder.length() > 1) {
                builder.append(", ");
            }
            builder.append("tokenValue=<TOKEN>");
        }
        this.display = builder.toString();
    }

    /**
     * The access token value used to authenticate the request (normally in an authorization header).
     * 
     * @return the tokenValue used to authenticate the request
     */
    public String getTokenValue() {
        return tokenValue;
    }

    /**
     * The access token type used to authenticate the request (normally in an authorization header).
     * 
     * @return the tokenType used to authenticate the request if known
     */
    public String getTokenType() {
        return tokenType;
    }

    /**
     * Indicates the TCP/IP address the authentication request was received from.
     * 
     * @return the address
     */
    public String getRemoteAddress() {
        return remoteAddress;
    }

    /**
     * Indicates the <code>HttpSession</code> id the authentication request was received from.
     * 
     * @return the session ID
     */
    public String getSessionId() {
        return sessionId;
    }

    /**
     * The authentication details obtained by decoding the access token
     * if available.
     * 
     * @return the decodedDetails if available (default null)
     */
    public Object getDecodedDetails() {
        return decodedDetails;
    }

    /**
     * The authentication details obtained by decoding the access token
     * if available.
     * 
     * @param decodedDetails the decodedDetails to set
     */
    public void setDecodedDetails(Object decodedDetails) {
        this.decodedDetails = decodedDetails;
    }

    @Override
    public String toString() {
        return display;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (sessionId == null ? 0 : sessionId.hashCode());
        result = prime * result + (tokenType == null ? 0 : tokenType.hashCode());
        result = prime * result + (tokenValue == null ? 0 : tokenValue.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        OAuth2AuthenticationDetails other = (OAuth2AuthenticationDetails) obj;
        if (sessionId == null) {
            if (other.sessionId != null) {
                return false;
            }
        } else if (!sessionId.equals(other.sessionId)) {
            return false;
        }
        if (tokenType == null) {
            if (other.tokenType != null) {
                return false;
            }
        } else if (!tokenType.equals(other.tokenType)) {
            return false;
        }
        if (tokenValue == null) {
            if (other.tokenValue != null) {
                return false;
            }
        } else if (!tokenValue.equals(other.tokenValue)) {
            return false;
        }
        return true;
    }


}
