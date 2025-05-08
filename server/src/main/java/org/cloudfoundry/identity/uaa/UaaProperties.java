package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.util.UaaStringUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.lang.Nullable;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Future replacement of {@link org.cloudfoundry.identity.uaa.impl.config.UaaConfiguration}
 * for binding properties and validating them.
 *
 * MAKE SURE TO EnableConfigurationProperties in {@link UaaConfig}
 */
public class UaaProperties {

    @ConfigurationProperties
    public record RootLevel(
            @DefaultValue("false") boolean require_https,
            @DefaultValue("loginsecret") String LOGIN_SECRET,
            @DefaultValue("false") boolean dump_requests,

            @DefaultValue("443") int https_port
    ) {

    }

    @ConfigurationProperties(prefix = "uaa")
    public record Uaa(String url) {
        public Uaa {
            if (url == null) {
                url = UaaStringUtils.DEFAULT_UAA_URL;
            }
        }
    }


    public record Saml(
            String activeKeyId,
            @DefaultValue("false") boolean disableInResponseToCheck,
            @DefaultValue("true") boolean wantAssertionSigned,
            @DefaultValue("true") boolean signRequest,
            String defaultIdentityProvider,
            Map<String, Map<String, String>> keys
    ){}

    @ConfigurationProperties(prefix = "login")
    public record Login(
            @DefaultValue(UaaStringUtils.DEFAULT_UAA_URL) String url,
            @DefaultValue("true") boolean selfServiceLinksEnabled,
            String homeRedirect,
            @DefaultValue("false") boolean idpDiscoveryEnabled,
            @DefaultValue("false") boolean accountChooserEnabled,
            String serviceProviderKey,
            String serviceProviderKeyPassword,
            String serviceProviderCertificate,
            String defaultIdentityProvider,
            Map<String, Object> branding,
            Saml saml
    ) {
    }


    public record LogoutRedirectParameter(
            @DefaultValue("false") boolean disable,
            List<String> whitelist
    ) {}

    public record LogoutRedirect(
            @DefaultValue("/login") String url,
            LogoutRedirectParameter parameter
    ){
        public LogoutRedirect {
            if (parameter == null) {
                parameter = new LogoutRedirectParameter(false, null);
            }
        }
    }

    @ConfigurationProperties(prefix = "logout")
    public record Logout(LogoutRedirect redirect) {
        public Logout {
            if (redirect == null) {
                redirect = new LogoutRedirect("/login", new LogoutRedirectParameter(false, Collections.emptyList()));
            }
        }
    }



    @ConfigurationProperties(prefix = "servlet")
    public record Servlet(
            SessionCookie sessionCookie,
            @DefaultValue("1800")
            int idleTimeout,
            @DefaultValue({"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Prefix", "Forwarded"})
            List<String> filteredHeaders
    ) {
        public Servlet {
            if (sessionCookie == null) {
                sessionCookie = new SessionCookie(true, null);
            }
        }
    }

    @ConfigurationProperties(prefix = "csp")
    public record Csp(
            @DefaultValue({"'self'"})
            List<String> scriptSrc
    )
    {}

    @ConfigurationProperties(prefix = "metrics")
    public record Metrics(
            @DefaultValue("true")
            boolean enabled,

            @DefaultValue("false")
            boolean perRequestMetrics
    )
    {}

    @ConfigurationProperties(prefix = "zones")
    public record Zones(@DefaultValue({}) Internal internal)
    {}

    public record Internal(Set<String> hostnames) {}

    public record SessionCookie(@DefaultValue("true") boolean encodeBase64, @Nullable Integer maxAge) {
    }

    @ConfigurationProperties(prefix = "oauth.client.secret.policy.global")
    record GlobalClientSecretPolicy (
            @DefaultValue("0") int minLength,
            @DefaultValue("255") int maxLength,
            @DefaultValue("0") int requireUpperCaseCharacter,
            @DefaultValue("0") int requireLowerCaseCharacter,
            @DefaultValue("0") int requireDigit,
            @DefaultValue("0") int requireSpecialCharacter,
            @DefaultValue("0") int expireSecretInMonths
    ) { }

    @ConfigurationProperties(prefix = "oauth.client.secret.policy")
    record DefaultClientSecretPolicy(
            GlobalClientSecretPolicy global,
            @DefaultValue("-1") int minLength,
            @DefaultValue("-1") int maxLength,
            @DefaultValue("-1") int requireUpperCaseCharacter,
            @DefaultValue("-1") int requireLowerCaseCharacter,
            @DefaultValue("-1") int requireDigit,
            @DefaultValue("-1") int requireSpecialCharacter,
            @DefaultValue("-1") int expireSecretInMonths

    ) {
        public DefaultClientSecretPolicy {
            if (global == null) {
                global = new GlobalClientSecretPolicy(0,255,0,0,0,0,0);
            }
            minLength = (minLength < 0) ? global.minLength : minLength;
            maxLength = (maxLength < 0) ? global.maxLength : maxLength;
            requireUpperCaseCharacter = (requireUpperCaseCharacter < 0) ? global.requireUpperCaseCharacter : requireUpperCaseCharacter;
            requireLowerCaseCharacter = (requireLowerCaseCharacter < 0) ? global.requireLowerCaseCharacter : requireLowerCaseCharacter;
            requireDigit = (requireDigit < 0) ? global.requireDigit : requireDigit;
            requireSpecialCharacter = (requireSpecialCharacter < 0) ? global.requireSpecialCharacter : requireSpecialCharacter;
            expireSecretInMonths = (expireSecretInMonths < 0) ? global.expireSecretInMonths : expireSecretInMonths;
        }
    }

}

