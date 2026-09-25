package org.cloudfoundry.identity.uaa.spiffe;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SpiffeIdTests {

    @Test
    void formatsWorkloadSpiffeId() {
        CfInstanceIdentity identity = new CfInstanceIdentity("org-1", "space-2", "app-3");

        String id = SpiffeId.format("example.org", identity, "web");

        assertThat(id).isEqualTo(
                "spiffe://example.org/cf/org/org-1/space/space-2/app/app-3/process/web");
    }

    @Test
    void formatsSshProcessType() {
        CfInstanceIdentity identity = new CfInstanceIdentity("o", "s", "a");

        assertThat(SpiffeId.format("td", identity, "ssh"))
                .isEqualTo("spiffe://td/cf/org/o/space/s/app/a/process/ssh");
    }

    /**
     * The three GUID segments come from certificate OU attributes, so they are as
     * attacker-influenced as the request body is. Anything outside the SPIFFE-ID character set
     * either forges a different identity (a {@code /} adds path segments) or makes the
     * newline-delimited proof-of-possession message ambiguous.
     */
    @Nested
    class PathSegmentValidation {

        @ParameterizedTest
        @ValueSource(strings = {"a/process/admin", "a/../b", "..", ".", "a b", "a\nb", "a\tb", "",
                "a%2Fb", "app:extra", "a+b", "a#b", "a?b"})
        void rejectsNonConformantOrgSegment(String org) {
            CfInstanceIdentity identity = new CfInstanceIdentity(org, "s", "a");

            assertThatThrownBy(() -> SpiffeId.format("td", identity, "web"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("org");
        }

        @ParameterizedTest
        @ValueSource(strings = {"s/process/admin", "..", "s\nx", ""})
        void rejectsNonConformantSpaceSegment(String space) {
            CfInstanceIdentity identity = new CfInstanceIdentity("o", space, "a");

            assertThatThrownBy(() -> SpiffeId.format("td", identity, "web"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("space");
        }

        @ParameterizedTest
        @ValueSource(strings = {"a/process/admin", "..", "a\nx", ""})
        void rejectsNonConformantAppSegment(String app) {
            CfInstanceIdentity identity = new CfInstanceIdentity("o", "s", app);

            assertThatThrownBy(() -> SpiffeId.format("td", identity, "web"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("app");
        }

        @ParameterizedTest
        @ValueSource(strings = {"web/../admin", "..", "web\nx", ""})
        void rejectsNonConformantProcessSegment(String processType) {
            CfInstanceIdentity identity = new CfInstanceIdentity("o", "s", "a");

            assertThatThrownBy(() -> SpiffeId.format("td", identity, processType))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("process");
        }

        @Test
        void rejectsNullSegment() {
            CfInstanceIdentity identity = new CfInstanceIdentity(null, "s", "a");

            assertThatThrownBy(() -> SpiffeId.format("td", identity, "web"))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void errorMessageDoesNotEchoTheCertificateSuppliedValue() {
            CfInstanceIdentity identity = new CfInstanceIdentity("a/process/injected", "s", "a");

            assertThatThrownBy(() -> SpiffeId.format("td", identity, "web"))
                    .hasMessageNotContaining("injected");
        }

        @Test
        void acceptsDotsDashesAndUnderscores() {
            CfInstanceIdentity identity = new CfInstanceIdentity("a.b", "c-d", "e_f");

            assertThat(SpiffeId.format("td", identity, "web"))
                    .isEqualTo("spiffe://td/cf/org/a.b/space/c-d/app/e_f/process/web");
        }

        @Test
        void rejectsSpiffeIdOverTheSpecifiedMaximumLength() {
            CfInstanceIdentity identity = new CfInstanceIdentity("a".repeat(2048), "s", "a");

            assertThatThrownBy(() -> SpiffeId.format("td", identity, "web"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("2048");
        }
    }

    @Nested
    class TrustDomainValidation {

        @ParameterizedTest
        @ValueSource(strings = {"EXAMPLE.org", "example.org/path", "exam ple.org", "example.org:443",
                "user@example.org", "example\norg"})
        void rejectsNonConformantTrustDomain(String trustDomain) {
            assertThatThrownBy(() -> SpiffeId.requireTrustDomain(trustDomain))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("uaa.spiffe.trust-domain");
        }

        @Test
        void rejectsMissingTrustDomain() {
            assertThatThrownBy(() -> SpiffeId.requireTrustDomain(null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must be set");
            assertThatThrownBy(() -> SpiffeId.requireTrustDomain(""))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must be set");
        }

        @Test
        void rejectsTrustDomainOverTheHostLengthLimit() {
            assertThatThrownBy(() -> SpiffeId.requireTrustDomain("a".repeat(256)))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void acceptsLowercaseDnsStyleTrustDomain() {
            assertThat(SpiffeId.requireTrustDomain("cf.example.org")).isEqualTo("cf.example.org");
        }
    }
}
