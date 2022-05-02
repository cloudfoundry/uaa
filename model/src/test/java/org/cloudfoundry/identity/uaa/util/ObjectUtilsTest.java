package org.cloudfoundry.identity.uaa.util;

import org.junit.jupiter.api.Test;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.ParserConfigurationException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

class ObjectUtilsTest {

  @Test
  void getDocumentBuilder() throws ParserConfigurationException {
    DocumentBuilder builder = ObjectUtils.getDocumentBuilder();
    assertNotNull(builder);
    assertNotNull(builder.getDOMImplementation());
    assertEquals(false, builder.isValidating());
    assertEquals(true, builder.isNamespaceAware());
    assertEquals(false, builder.isXIncludeAware());
  }
}
