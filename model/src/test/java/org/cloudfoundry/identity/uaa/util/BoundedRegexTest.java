package org.cloudfoundry.identity.uaa.util;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

class BoundedRegexTest {

    @ParameterizedTest
    @ValueSource(strings = {
            ".*",
            "^https://.*\\.example\\.com$",
            "example\\.com",
            "^/uaa/(userinfo|logout\\.do)$",
            "^https://([a-z0-9-]{1,63}\\.){1,5}example\\.com$",
            "^(\\d{1,3}\\.){3}\\d{1,3}$",
            "(?i)^HTTPS://EXAMPLE\\.COM$"
    })
    void acceptsPatternsTypicalOfCorsConfiguration(String regex) {
        assertThat(BoundedRegex.compile(regex)).isNotNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "^https://(?=example)example\\.com$",
            "^(?<!x)example$",
            "(a)\\1",
            "a++",
            "(?>a)b"
    })
    void rejectsConstructsThatNeedBacktracking(String regex) {
        assertThatThrownBy(() -> BoundedRegex.compile(regex)).isInstanceOf(PatternSyntaxException.class);
    }

    @Test
    void rejectsPatternsLongerThanTheLimit() {
        assertThat(BoundedRegex.compile("a".repeat(BoundedRegex.MAX_PATTERN_LENGTH))).isNotNull();
        assertThatThrownBy(() -> BoundedRegex.compile("a".repeat(BoundedRegex.MAX_PATTERN_LENGTH + 1)))
                .isInstanceOf(PatternSyntaxException.class);
    }

    @Test
    void rejectsHugePatternsWithoutCompilingThem() {
        String huge = "a".repeat(1_000_000);
        assertTimeoutPreemptively(Duration.ofSeconds(2),
                () -> assertThatThrownBy(() -> BoundedRegex.compile(huge)).isInstanceOf(PatternSyntaxException.class));
    }

    @Test
    void rejectsNestedCountedRepetitionsBeforeTheyExhaustMemory() {
        assertTimeoutPreemptively(Duration.ofSeconds(2), () -> {
            assertThatThrownBy(() -> BoundedRegex.compile("((((a{1000}){1000}){1000}){1000})")).isInstanceOf(PatternSyntaxException.class);
            assertThatThrownBy(() -> BoundedRegex.compile("(a{2,1000}){2,1000}")).isInstanceOf(PatternSyntaxException.class);
            assertThatThrownBy(() -> BoundedRegex.compile("(a{1000,}){2}")).isInstanceOf(PatternSyntaxException.class);
        });
    }

    @Test
    void repetitionProductLimitIsExact() {
        assertThat(BoundedRegex.compile("x{1000}")).isNotNull();
        assertThat(BoundedRegex.compile("(x{500}){2}")).isNotNull();
        assertThatThrownBy(() -> BoundedRegex.compile("x{1001}")).isInstanceOf(PatternSyntaxException.class);
        assertThatThrownBy(() -> BoundedRegex.compile("(x{500}){3}")).isInstanceOf(PatternSyntaxException.class);
    }

    @Test
    void rejectsLongRepeatedGroupsBeforeCompilingThem() {
        // 490 characters repeated 1000 times would compile to about 480,000 instructions and tens of MB.
        String regex = "(?:" + "a".repeat(480) + "){1000}";
        assertTimeoutPreemptively(Duration.ofSeconds(2), () ->
                assertThatThrownBy(() -> BoundedRegex.compile(regex)).isInstanceOf(PatternSyntaxException.class));
    }

    @Test
    void programSizeLimitIsExact() {
        // Each repetition adds 36 instructions: 52 compile to 1978 and 53 to 2016 (limit 2000).
        assertThat(BoundedRegex.compile("(abcdefghijklmnopqrstuvwxyz0123456789){52}").programSize())
                .isLessThanOrEqualTo(BoundedRegex.MAX_PROGRAM_SIZE);
        assertThatThrownBy(() -> BoundedRegex.compile("(abcdefghijklmnopqrstuvwxyz0123456789){53}"))
                .isInstanceOf(PatternSyntaxException.class);
    }

    @Test
    void rejectsPatternsThatCompileToTooLargeAProgram() {
        // 36 characters repeated 60 times: well under the length and repetition limits, but about 2,160 instructions.
        String regex = "(abcdefghijklmnopqrstuvwxyz0123456789){60}";
        assertThatThrownBy(() -> BoundedRegex.compile(regex)).isInstanceOf(PatternSyntaxException.class);
    }

    @Test
    void matchesCatastrophicPatternsInLinearTime() {
        Pattern pattern = BoundedRegex.compile("^(https?://)?(([a-z0-9]+)+\\.)+$");
        assertTimeoutPreemptively(Duration.ofSeconds(1),
                () -> assertThat(pattern.matcher("https://" + "a".repeat(2000) + "!").matches()).isFalse());
    }

    @Test
    void limitsTheNumberOfPatternsInAList() {
        Pattern pattern = BoundedRegex.compile("example\\.com");
        assertThat(BoundedRegex.withinListLimits(Collections.nCopies(BoundedRegex.MAX_PATTERNS, pattern))).isTrue();
        assertThat(BoundedRegex.withinListLimits(Collections.nCopies(BoundedRegex.MAX_PATTERNS + 1, pattern))).isFalse();
    }

    @Test
    void limitsTheTotalProgramSizeOfAList() {
        Pattern large = BoundedRegex.compile("[a-z]{1000}");
        List<Pattern> patterns = Collections.nCopies(BoundedRegex.MAX_TOTAL_PROGRAM_SIZE / large.programSize() + 1, large);
        assertThat(BoundedRegex.withinListLimits(patterns)).isFalse();
    }
}
