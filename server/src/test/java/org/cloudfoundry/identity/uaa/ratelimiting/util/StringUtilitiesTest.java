package org.cloudfoundry.identity.uaa.ratelimiting.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

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
        assertNull(StringUtilities.toErrorMsg(null));
        assertEquals("Fred", StringUtilities.toErrorMsg(new IllegalStateException("Fred")));
        assertEquals(MyException.class.getSimpleName(), StringUtilities.toErrorMsg(new MyException()));
    }

    @Test
    void options() {
        String expectedEMPTY = "";
        String expectedJUSTNULLS = "null";
        String expectedVALUES = "'Martin Fowler', 7, null, 2, or 5"; // Note in reverse order

        assertEquals(expectedEMPTY, StringUtilities.options(EMPTY), "EMPTY");
        assertEquals(expectedJUSTNULLS, StringUtilities.options(JUST_NULLS), "JUST_NULLS");
        assertEquals(expectedVALUES, StringUtilities.options(VALUES), "VALUES");

        String oneLabel = "type";
        assertEquals("no " + oneLabel + "s" + expectedEMPTY, StringUtilities.options(oneLabel, EMPTY), "EMPTY 1label");
        assertEquals("the " + oneLabel + " is: " + expectedJUSTNULLS, StringUtilities.options(oneLabel, JUST_NULLS), "JUST_NULLS 1label");
        assertEquals("the " + oneLabel + "s are: " + expectedVALUES, StringUtilities.options(oneLabel, VALUES), "VALUES 1label");

        String labelSingular = "child";
        String labelPlural = "children";
        assertEquals("no " + labelPlural + expectedEMPTY, StringUtilities.options(labelSingular, labelPlural, EMPTY), "EMPTY 2labels");
        assertEquals("the " + labelSingular + " is: " + expectedJUSTNULLS, StringUtilities.options(labelSingular, labelPlural, JUST_NULLS), "JUST_NULLS 2labels");
        assertEquals("the " + labelPlural + " are: " + expectedVALUES, StringUtilities.options(labelSingular, labelPlural, VALUES), "VALUES 2labels");
    }
}