package org.cloudfoundry.identity.uaa.account;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.cloudfoundry.identity.uaa.constants.ClientAuthentication;

@Data
@NoArgsConstructor
public class OpenIdConfiguration {

    @JsonProperty("issuer")
    private String issuer;

    @JsonProperty("authorization_endpoint")
    private String authUrl;

    @JsonProperty("token_endpoint")
    private String tokenUrl;

    @JsonProperty("token_endpoint_auth_methods_supported")
    private String[] tokenAMR = new String[]{ClientAuthentication.CLIENT_SECRET_BASIC, ClientAuthentication.CLIENT_SECRET_POST, ClientAuthentication.PRIVATE_KEY_JWT};

    @JsonProperty("token_endpoint_auth_signing_alg_values_supported")
    private String[] tokenEndpointAuthSigningValues = new String[]{"RS256", "HS256"};

    @JsonProperty("userinfo_endpoint")
    private String userInfoUrl;

    @JsonProperty("jwks_uri")
    private String jwksUri;

    @JsonProperty("end_session_endpoint")
    private String logoutEndpoint;

    @JsonProperty("scopes_supported")
    private String[] scopes = new String[]{"openid", "profile", "email", "phone", "roles", "user_attributes"};

    @JsonProperty("response_types_supported")
    private String[] responseTypes = new String[]{"code", "code id_token", "id_token", "token id_token"};

    @JsonProperty("subject_types_supported")
    private String[] subjectTypesSupported = new String[]{"public"};

    @JsonProperty("id_token_signing_alg_values_supported")
    private String[] idTokenSigningAlgValues = new String[]{"RS256", "HS256"};

    @JsonProperty("id_token_encryption_alg_values_supported")
    private String[] requestObjectSigningAlgValues = new String[]{"none"};

    @JsonProperty("claim_types_supported")
    private String[] claimTypesSupported = new String[]{"normal"};

    @JsonProperty("claims_supported")
    private String[] claimsSupported = new String[]{"sub", "user_name", "origin", "iss", "auth_time", "amr", "acr", "client_id",
            "aud", "zid", "grant_type", "user_id", "azp", "scope", "exp", "iat", "jti", "rev_sig", "cid", "given_name", "family_name", "phone_number", "email"};

    @JsonProperty("claims_parameter_supported")
    private boolean claimsParameterSupported;

    @JsonProperty("service_documentation")
    private String serviceDocumentation = "http://docs.cloudfoundry.org/api/uaa/";

    @JsonProperty("ui_locales_supported")
    private String[] uiLocalesSupported = new String[]{"en-US"};

    @JsonProperty("code_challenge_methods_supported")
    private String[] codeChallengeMethodsSupported = new String[]{"S256", "plain"};

    public OpenIdConfiguration(final String contextPath, final String issuer) {
        this.issuer = issuer;
        this.authUrl = contextPath + "/oauth/authorize";
        this.tokenUrl = contextPath + "/oauth/token";
        this.userInfoUrl = contextPath + "/userinfo";
        this.jwksUri = contextPath + "/token_keys";
        this.logoutEndpoint = contextPath + "/logout.do";
    }
}
