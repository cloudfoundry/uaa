package org.cloudfoundry.identity.uaa.oauth.client;

import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


class ClientJwtCredentialTest {

    @Test
    void parse() {
        assertThat(ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"}]")).isInstanceOf(List.class);
        List<ClientJwtCredential> federationList = ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"},{\"iss\":\"http://localhost:8080/uaa\", \"sub\":\"another_client\"}]");
        assertThat(federationList).hasSize(2);
    }

    @Test
    void constructor() {
        ClientJwtCredential jwtCredential = new ClientJwtCredential("subject", "issuer", "audience");
        assertThat(jwtCredential.getSubject()).isEqualTo("subject");
        assertThat(jwtCredential.getIssuer()).isEqualTo("issuer");
        assertThat(jwtCredential.getAudience()).isEqualTo("audience");
    }

    @Test
    void deserializerConstructorException() {
        assertThatThrownBy(() -> ClientJwtCredential.parse("[{\"iss\":\"http://localhost:8080/uaa\",\"sub\":\"client_with_jwks_trust\"},{\"iss\":\"http://localhost:8080/uaa\"}]"))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Client jwt configuration cannot be parsed");
        assertThatThrownBy(() -> ClientJwtCredential.parse("[{\"sub\":\"client_with_jwks_trust\"}]"))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Client jwt configuration cannot be parsed");
        assertThatThrownBy(() -> ClientJwtCredential.parse("[{\"unknown\":\"client_with_jwks_trust\"}]"))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Client jwt configuration cannot be parsed");
    }

    @Test
    void deserializerParserException() {
        assertThatThrownBy(() -> ClientJwtCredential.parse("[\"iss\":\"issuer\"]"))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("Client jwt configuration cannot be parsed");
    }

    @Test
    void testHashCode() {
        assertThat(new ClientJwtCredential("subject", "issuer", "audience")).hasSameHashCodeAs(new ClientJwtCredential("subject", "issuer", "audience"));
        assertThat(new ClientJwtCredential("subject", "issuer", "audience")).doesNotHaveSameHashCodeAs(new ClientJwtCredential("subject", "issuer", null));
    }

    @Test
    void equals() {
        assertThat(new ClientJwtCredential("subject", "issuer", "audience")).isEqualTo(new ClientJwtCredential("subject", "issuer", "audience"));
        assertThat(new ClientJwtCredential("subject", "issuer", "audience")).isNotEqualTo(new ClientJwtCredential("subject", "issuer", null));
    }

    @Nested
    class SubjectPattern {

        private static final String GITLAB_PATTERN = "project_path:myteam/deploy:ref_type:branch:ref:*";

        @Test
        void exactCredentialIsNotAPattern() {
            ClientJwtCredential credential = new ClientJwtCredential("subject", "issuer", "audience");
            assertThat(credential.isSubjectPattern()).isFalse();
            assertThat(credential.getSubjectPattern()).isNull();
            assertThat(credential.matchesSubject("subject")).isTrue();
            assertThat(credential.matchesSubject("subjectX")).isFalse();
            assertThat(credential.matchesSubject(null)).isFalse();
        }

        @Test
        void patternIsMirroredIntoSubject() {
            ClientJwtCredential credential = new ClientJwtCredential(null, "issuer", null, GITLAB_PATTERN);
            assertThat(credential.isSubjectPattern()).isTrue();
            assertThat(credential.getSubjectPattern()).isEqualTo(GITLAB_PATTERN);
            // keeps subject non-null for credKey/equals/delete, and makes a node that does not
            // know sub_pattern compare the pattern text literally and so fail closed
            assertThat(credential.getSubject()).isEqualTo(GITLAB_PATTERN);
        }

        @ParameterizedTest
        @CsvSource(delimiter = '|', value = {
                "project_path:myteam/deploy:ref_type:branch:ref:* | project_path:myteam/deploy:ref_type:branch:ref:main",
                "project_path:myteam/deploy:ref_type:branch:ref:* | project_path:myteam/deploy:ref_type:branch:ref:feature/nested",
                "project_path:myteam/deploy:ref_type:branch:ref:* | project_path:myteam/deploy:ref_type:branch:ref:release/1.0",
                "repo:octo-org/octo-repo:ref:refs/heads/*         | repo:octo-org/octo-repo:ref:refs/heads/demo-branch",
                "repo:octo-org/octo-repo:environment:*            | repo:octo-org/octo-repo:environment:Production",
        })
        void matchesSubject(String pattern, String assertedSubject) {
            assertThat(new ClientJwtCredential(null, "issuer", null, pattern).matchesSubject(assertedSubject)).isTrue();
        }

        @ParameterizedTest
        @CsvSource(delimiter = '|', value = {
                // a wildcard must not swallow further claim components
                "project_path:myteam/deploy:ref_type:branch:ref:* | project_path:myteam/deploy:ref_type:branch:ref:main:evil",
                // a wildcard must not authorise a different project
                "project_path:myteam/*:ref_type:branch:ref:*      | project_path:otherteam/deploy:ref_type:branch:ref:main",
                // anchored at both ends
                "repo:org/repo:ref:*                              | PREFIXrepo:org/repo:ref:main",
                // '.' is a literal
                "project_path:team/a.b:ref:*                      | project_path:team/aXb:ref:main",
        })
        void doesNotMatchSubject(String pattern, String assertedSubject) {
            assertThat(new ClientJwtCredential(null, "issuer", null, pattern).matchesSubject(assertedSubject)).isFalse();
        }

        @Test
        void rejectsOverlongAssertedSubject() {
            ClientJwtCredential credential = new ClientJwtCredential(null, "issuer", null, "repo:org/r:ref:*");
            assertThat(credential.matchesSubject("repo:org/r:ref:" + "a".repeat(MAX_LENGTH))).isFalse();
        }

        @ParameterizedTest
        @ValueSource(strings = {
                "*",            // would trust any subject from the issuer
                "*:*",          // no literal context
                "**",
                "no-wildcard-at-all",
                "repo:org/r:*:*:*:*:*:*",
        })
        void rejectsInvalidPattern(String pattern) {
            assertThatThrownBy(() -> new ClientJwtCredential(null, "issuer", null, pattern))
                    .isInstanceOf(IllegalArgumentException.class).hasMessage("Invalid federated jwt credentials");
        }

        @Test
        void rejectsOverlongPattern() {
            String pattern = "repo:org/" + "a".repeat(MAX_LENGTH) + ":*";
            assertThatThrownBy(() -> new ClientJwtCredential(null, "issuer", null, pattern))
                    .isInstanceOf(IllegalArgumentException.class).hasMessage("Invalid federated jwt credentials");
        }

        @Test
        void rejectsConflictingSubjectAndPattern() {
            assertThatThrownBy(() -> new ClientJwtCredential("some-other-subject", "issuer", null, GITLAB_PATTERN))
                    .isInstanceOf(IllegalArgumentException.class).hasMessage("Invalid federated jwt credentials");
        }

        @Test
        void patternIsNotEqualToExactCredentialOfSameText() {
            ClientJwtCredential pattern = new ClientJwtCredential(null, "issuer", null, GITLAB_PATTERN);
            ClientJwtCredential exact = new ClientJwtCredential(GITLAB_PATTERN, "issuer", null);
            assertThat(pattern).isNotEqualTo(exact);
            assertThat(pattern).doesNotHaveSameHashCodeAs(exact);
        }

        @Test
        void serializesExactCredentialUnchanged() {
            // pins the on-disk shape of existing client_jwt_config rows
            assertThat(JsonUtils.writeValueAsString(new ClientJwtCredential("subject", "issuer", "audience")))
                    .isEqualTo("{\"sub\":\"subject\",\"iss\":\"issuer\",\"aud\":\"audience\"}");
        }

        @Test
        void roundTripsPattern() {
            List<ClientJwtCredential> parsed = ClientJwtCredential.parse(
                    "[{\"iss\":\"https://gitlab.example.com\",\"sub_pattern\":\"" + GITLAB_PATTERN + "\"}]");
            assertThat(parsed).hasSize(1);
            assertThat(parsed.getFirst().isSubjectPattern()).isTrue();
            assertThat(parsed.getFirst().matchesSubject("project_path:myteam/deploy:ref_type:branch:ref:main")).isTrue();
            assertThat(JsonUtils.writeValueAsString(parsed.getFirst()))
                    .contains("\"sub_pattern\":\"" + GITLAB_PATTERN + "\"");
        }

        private static final int MAX_LENGTH = 256;
    }
}
