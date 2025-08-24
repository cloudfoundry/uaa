package org.cloudfoundry.identity.uaa.ratelimiting.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class StringUtilitiesTest {
    private static final Object[] EMPTY = new Object[0];
    private static final Object[] JUST_NULLS = new Object[]{null};
    private static final Object[] VALUES = new Object[]{5, 2, null, 7, "Martin Fowler"};

    private static class MyException extends Exception {
        @Override
        public String getMessage() {
            return null;
        }
    }

    @Test
    void toErrorMsg() {
        assertThat(StringUtilities.toErrorMsg(null)).isNull();
        assertThat(StringUtilities.toErrorMsg(new IllegalStateException("Fred"))).isEqualTo("Fred");
        assertThat(StringUtilities.toErrorMsg(new MyException())).isEqualTo(MyException.class.getSimpleName());
    }

    @Test
    void options() {
        String expectedEMPTY = "";
        String expectedJUSTNULLS = "null";
        String expectedVALUES = "'Martin Fowler', 7, null, 2, or 5"; // Note in reverse order

        assertThat(StringUtilities.options(EMPTY)).as("EMPTY").isEqualTo(expectedEMPTY);
        assertThat(StringUtilities.options(JUST_NULLS)).as("JUST_NULLS").isEqualTo(expectedJUSTNULLS);
        assertThat(StringUtilities.options(VALUES)).as("VALUES").isEqualTo(expectedVALUES);

        String oneLabel = "type";
        assertThat(StringUtilities.options(oneLabel, EMPTY)).as("EMPTY 1label").isEqualTo("no " + oneLabel + "s" + expectedEMPTY);
        assertThat(StringUtilities.options(oneLabel, JUST_NULLS)).as("JUST_NULLS 1label").isEqualTo("the " + oneLabel + " is: " + expectedJUSTNULLS);
        assertThat(StringUtilities.options(oneLabel, VALUES)).as("VALUES 1label").isEqualTo("the " + oneLabel + "s are: " + expectedVALUES);

        String labelSingular = "child";
        String labelPlural = "children";
        assertThat(StringUtilities.options(labelSingular, labelPlural, EMPTY)).as("EMPTY 2labels").isEqualTo("no " + labelPlural + expectedEMPTY);
        assertThat(StringUtilities.options(labelSingular, labelPlural, JUST_NULLS)).as("JUST_NULLS 2labels").isEqualTo("the " + labelSingular + " is: " + expectedJUSTNULLS);
        assertThat(StringUtilities.options(labelSingular, labelPlural, VALUES)).as("VALUES 2labels").isEqualTo("the " + labelPlural + " are: " + expectedVALUES);
    }
}