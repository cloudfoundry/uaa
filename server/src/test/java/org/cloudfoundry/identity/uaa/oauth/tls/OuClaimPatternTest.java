package org.cloudfoundry.identity.uaa.oauth.tls;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.regex.PatternSyntaxException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OuClaimPatternTest {

    @ParameterizedTest
    @ValueSource(strings = {
            "(a){2}",
            "(?:ab){2,}",
            "((a){2}){2}",
            "(a\\\\){2}",
            "[)](b){3}",
            "[]](b){3}",
            "[^]](b){3}",
            "[[:alpha:]](b){3}",
            "\\Q)\\E(x){2}",
            "(?i){2}"
    })
    void rejectsCountedGroups(String source) {
        assertThatThrownBy(() -> OuClaimPattern.compile(source))
                .isInstanceOf(PatternSyntaxException.class)
                .hasMessageContaining("Counted repetitions of groups are not supported");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "^space:(.+)$",
            "(ab)+",
            "a{2}",
            "[a-z]{2,5}",
            "(team\\){2})",
            "[)]{2}",
            "[\\]){2}]",
            "(a)\\{2}",
            "\\Q){2}\\E",
            "(x)\\Q){2}"
    })
    void acceptsCountedLiteralsAndUncountedGroups(String source) {
        assertThat(OuClaimPattern.compile(source)).isNotNull();
    }

    @Test
    void escapedParenthesisRepetitionMatchesLiterally() {
        assertThat(OuClaimPattern.compile("(team\\){2})").matcher("team))").matches()).isTrue();
        assertThat(OuClaimPattern.compile("(team\\){2})").matcher("team)").matches()).isFalse();
    }

    @Test
    void rejectsOverlongSource() {
        assertThatThrownBy(() -> OuClaimPattern.compile("a".repeat(257)))
                .isInstanceOf(PatternSyntaxException.class)
                .hasMessageContaining("256");
    }
}
