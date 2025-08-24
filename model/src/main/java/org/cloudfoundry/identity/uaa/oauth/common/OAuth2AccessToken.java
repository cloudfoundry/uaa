package org.cloudfoundry.identity.uaa.oauth.common;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.Date;
import java.util.Map;
import java.util.Set;

/**
 * Moved class implementation of from spring-security-oauth2 into UAA
 *
 * The class was taken over from the legacy project with minor refactorings
 * based on sonar.
 *
 * Scope: OAuth2 client
 */
@JsonSerialize(using = OAuth2AccessTokenJackson2Serializer.class)
@JsonDeserialize(using = OAuth2AccessTokenJackson2Deserializer.class)
public interface OAuth2AccessToken {

    public static String BEARER_TYPE = "Bearer";

    public static String OAUTH2_TYPE = "OAuth2";

    /**
     * The access token issued by the authorization server. This value is REQUIRED.
     */
    public static String ACCESS_TOKEN = "access_token";

    /**
     * The type of the token issued as described in <a
     * href="https://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-7.1">Section 7.1</a>. Value is case insensitive.
     * This value is REQUIRED.
     */
    public static String TOKEN_TYPE = "token_type";

    /**
     * The lifetime in seconds of the access token. For example, the value "3600" denotes that the access token will
     * expire in one hour from the time the response was generated. This value is OPTIONAL.
     */
    public static String EXPIRES_IN = "expires_in";

    /**
     * The refresh token which can be used to obtain new access tokens using the same authorization grant as described
     * in <a href="https://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-6">Section 6</a>. This value is OPTIONAL.
     */
    public static String REFRESH_TOKEN = "refresh_token";

    /**
     * The scope of the access token as described by <a
     * href="https://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-3.3">Section 3.3</a>
     */
    public static String SCOPE = "scope";

    /**
     * The additionalInformation map is used by the token serializers to export any fields used by extensions of OAuth.
     * @return a map from the field name in the serialized token to the value to be exported. The default serializers 
     * make use of Jackson's automatic JSON mapping for Java objects (for the Token Endpoint flows) or implicitly call 
     * .toString() on the "value" object (for the implicit flow) as part of the serialization process.
     */
    Map<String, Object> getAdditionalInformation();

    Set<String> getScope();

    OAuth2RefreshToken getRefreshToken();

    String getTokenType();

    boolean isExpired();

    Date getExpiration();

    int getExpiresIn();

    String getValue();

}
