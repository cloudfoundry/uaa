package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;

import java.util.ArrayList;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

class ObjectUtilsTest {

  private static final Object[] NULLARRAY = null;
  private static final Object[] EMPTY = {};
  private static final Object[] JUST_NULLS = {null};
  private static final Object[] VALUES = {5, 2, null, 7, "Martin Fowler"};

  @Test
  void countNonNull() {
    Assertions.assertEquals( 0, ObjectUtils.countNonNull( NULLARRAY ), "NULLARRAY" );
    Assertions.assertEquals( 0, ObjectUtils.countNonNull( EMPTY ), "EMPTY" );
    Assertions.assertEquals( 0, ObjectUtils.countNonNull( JUST_NULLS ), "JUST_NULLS" );
    Assertions.assertEquals( 4, ObjectUtils.countNonNull( VALUES ), "VALUES" );
  }

  @Test
  void getDocumentBuilder() throws ParserConfigurationException {
    DocumentBuilder builder = ObjectUtils.getDocumentBuilder();
    assertNotNull(builder);
    assertNotNull(builder.getDOMImplementation());
    assertEquals(false, builder.isValidating());
    assertEquals(true, builder.isNamespaceAware());
    assertEquals(false, builder.isXIncludeAware());
  }

  @Test
  void isNotExmpty() {
    assertTrue(ObjectUtils.isNotEmpty(Arrays.asList("1")));
    assertFalse(ObjectUtils.isNotEmpty(new ArrayList<>()));
    assertFalse(ObjectUtils.isNotEmpty(null));
  }
}
