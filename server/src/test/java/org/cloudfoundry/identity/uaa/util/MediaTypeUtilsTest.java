package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.MediaType;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MediaTypeUtilsTest {

    @Test
    void sortByQualityValueWithNullThrowsException() {
        assertThatThrownBy(() -> MediaTypeUtils.sortByQualityValue(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'mediaTypes' must not be null");
    }

    @ParameterizedTest
    @MethodSource("listsThatShouldNotBeSorted")
    void sortByQualityValueWithListsThatDoNotNeedSorting(List<MediaType> mediaTypes, List<MediaType> expected) {
        MediaTypeUtils.sortByQualityValue(mediaTypes);
        assertThat(mediaTypes).containsExactlyElementsOf(expected);
    }

    static Stream<Arguments> listsThatShouldNotBeSorted() {
        return Stream.of(
                Arguments.of(Collections.emptyList(), Collections.emptyList()),
                Arguments.of(Collections.singletonList(MediaType.APPLICATION_JSON), Collections.singletonList(MediaType.APPLICATION_JSON))
        );
    }

    @Test
    void sortByQualityValueProducesCorrectOrder() {
        MediaType audioBasic = new MediaType("audio", "basic");
        MediaType audio = new MediaType("audio");
        MediaType audio03 = new MediaType("audio", "*", 0.3);
        MediaType audio07 = new MediaType("audio", "*", 0.7);
        MediaType audioBasicLevel = new MediaType("audio", "basic", Collections.singletonMap("level", "1"));
        MediaType all = MediaType.ALL;

        List<MediaType> expected = new ArrayList<>();
        expected.add(audioBasicLevel);
        expected.add(audioBasic);
        expected.add(audio);
        expected.add(all);
        expected.add(audio07);
        expected.add(audio03);

        List<MediaType> result = new ArrayList<>(expected);
        Random rnd = new Random(0);
        for (int i = 0; i < 10; i++) {
            Collections.shuffle(result, rnd);
            MediaTypeUtils.sortByQualityValue(result);

            for (int j = 0; j < result.size(); j++) {
                assertThat(result.get(j)).as("Invalid media type at " + j).isSameAs(expected.get(j));
            }
        }
    }

    @Test
    void sortByQualityValueIsStableForEquallyRankedTypes() {
        MediaType audioBasic = new MediaType("audio", "basic");
        MediaType textHtml = new MediaType("text", "html");
        MediaType audioWave = new MediaType("audio", "wave");

        List<MediaType> input = new ArrayList<>(List.of(audioBasic, textHtml, audioWave));
        MediaTypeUtils.sortByQualityValue(input);

        assertThat(input).containsExactly(audioBasic, textHtml, audioWave);
    }

    @Test
    void byQualityValueComparatorHandlesAllScenarios() {
        MediaType audioBasic = new MediaType("audio", "basic");
        MediaType audioWave = new MediaType("audio", "wave");
        MediaType audio = new MediaType("audio");
        MediaType audio03 = new MediaType("audio", "*", 0.3);
        MediaType audio07 = new MediaType("audio", "*", 0.7);
        MediaType audioBasicLevel = new MediaType("audio", "basic", Collections.singletonMap("level", "1"));
        MediaType textHtml = new MediaType("text", "html");
        MediaType allXml = new MediaType("application", "*+xml");
        MediaType all = MediaType.ALL;

        Comparator<MediaType> comp = MediaTypeUtils.BY_QUALITY_VALUE;

        // equal
        assertThat(comp.compare(audioBasic, audioBasic)).as("Invalid comparison result").isZero();
        assertThat(comp.compare(audio, audio)).as("Invalid comparison result").isZero();
        assertThat(comp.compare(audio07, audio07)).as("Invalid comparison result").isZero();
        assertThat(comp.compare(audio03, audio03)).as("Invalid comparison result").isZero();
        assertThat(comp.compare(audioBasicLevel, audioBasicLevel)).as("Invalid comparison result").isZero();

        // specific to unspecific
        assertThat(comp.compare(audioBasic, audio)).as("Invalid comparison result").isNegative();
        assertThat(comp.compare(audioBasic, all)).as("Invalid comparison result").isNegative();
        assertThat(comp.compare(audio, all)).as("Invalid comparison result").isNegative();
        assertThat(comp.compare(MediaType.APPLICATION_XHTML_XML, allXml)).as("Invalid comparison result").isNegative();

        // unspecific to specific
        assertThat(comp.compare(audio, audioBasic)).as("Invalid comparison result").isPositive();
        assertThat(comp.compare(all, audioBasic)).as("Invalid comparison result").isPositive();
        assertThat(comp.compare(all, audio)).as("Invalid comparison result").isPositive();
        assertThat(comp.compare(allXml, MediaType.APPLICATION_XHTML_XML)).as("Invalid comparison result").isPositive();

        // qualifiers
        assertThat(comp.compare(audio, audio07)).as("Invalid comparison result").isNegative();
        assertThat(comp.compare(audio07, audio)).as("Invalid comparison result").isPositive();
        assertThat(comp.compare(audio07, audio03)).as("Invalid comparison result").isNegative();
        assertThat(comp.compare(audio03, audio07)).as("Invalid comparison result").isPositive();
        assertThat(comp.compare(audio03, all)).as("Invalid comparison result").isPositive();
        assertThat(comp.compare(all, audio03)).as("Invalid comparison result").isNegative();

        // other parameters
        assertThat(comp.compare(audioBasic, audioBasicLevel)).as("Invalid comparison result").isPositive();
        assertThat(comp.compare(audioBasicLevel, audioBasic)).as("Invalid comparison result").isNegative();

        // different types
        assertThat(comp.compare(audioBasic, textHtml)).as("Invalid comparison result").isZero();
        assertThat(comp.compare(textHtml, audioBasic)).as("Invalid comparison result").isZero();

        // different subtypes
        assertThat(comp.compare(audioBasic, audioWave)).as("Invalid comparison result").isZero();
        assertThat(comp.compare(audioWave, audioBasic)).as("Invalid comparison result").isZero();
    }
}
