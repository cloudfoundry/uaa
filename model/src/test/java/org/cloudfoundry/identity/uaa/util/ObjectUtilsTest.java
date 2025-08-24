package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.Test;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ObjectUtilsTest {

    private static final Object[] NULLARRAY = null;
    private static final Object[] EMPTY = {};
    private static final Object[] JUST_NULLS = {null};
    private static final Object[] VALUES = {5, 2, null, 7, "Martin Fowler"};

    @Test
    void countNonNull() {
        assertThat(ObjectUtils.countNonNull(NULLARRAY)).as("NULLARRAY").isZero();
        assertThat(ObjectUtils.countNonNull(EMPTY)).as("EMPTY").isZero();
        assertThat(ObjectUtils.countNonNull(JUST_NULLS)).as("JUST_NULLS").isZero();
        assertThat(ObjectUtils.countNonNull(VALUES)).as("VALUES").isEqualTo(4);
    }

    @Test
    void getDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilder builder = ObjectUtils.getDocumentBuilder();
        assertThat(builder).isNotNull();
        assertThat(builder.getDOMImplementation()).isNotNull();
        assertThat(builder.isValidating()).isFalse();
        assertThat(builder.isNamespaceAware()).isTrue();
        assertThat(builder.isXIncludeAware()).isFalse();
    }

    @Test
    void isNotEmpty_isEmpty() {
        final List<String> object1 = List.of("1");
        assertThat(ObjectUtils.isNotEmpty(object1)).isTrue();
        assertThat(ObjectUtils.isEmpty(object1)).isFalse();

        final ArrayList<Object> object2 = new ArrayList<>();
        assertThat(ObjectUtils.isNotEmpty(object2)).isFalse();
        assertThat(ObjectUtils.isEmpty(object2)).isTrue();

        assertThat(ObjectUtils.isNotEmpty(null)).isFalse();
        assertThat(ObjectUtils.isEmpty(null)).isTrue();
    }
}
