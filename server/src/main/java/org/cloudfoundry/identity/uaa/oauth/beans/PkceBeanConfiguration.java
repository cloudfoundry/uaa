package org.cloudfoundry.identity.uaa.oauth.beans;

import org.cloudfoundry.identity.uaa.oauth.pkce.PkceValidationService;
import org.cloudfoundry.identity.uaa.oauth.pkce.PkceVerifier;
import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.PlainPkceVerifier;
import org.cloudfoundry.identity.uaa.oauth.pkce.verifiers.S256PkceVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

import static java.util.Map.entry;
import static java.util.Map.ofEntries;

@Configuration
public class PkceBeanConfiguration {

    @Bean
    S256PkceVerifier s256PkceVerifier() {
        return new S256PkceVerifier();
    }

    @Bean
    PlainPkceVerifier plainPkceVerifier() {
        return new PlainPkceVerifier();
    }

    @Bean
    Map<String, PkceVerifier> codeChallengeMethods() {
        return ofEntries(
                entry("S256", s256PkceVerifier()),
                entry("plain", plainPkceVerifier())
        );
    }

    @Bean
    PkceValidationService pkceValidationServices() {
        return new PkceValidationService(codeChallengeMethods());
    }
}
