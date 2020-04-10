package org.cloudfoundry.identity.uaa.impl;

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/** JSON deserializer for Jackson to handle regular date instances as timestamps in ISO format. */
public class JsonDateDeserializer extends JsonDeserializer<Date> {

  public static final String DATE_FORMATTER = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

  public static Date getDate(String text, JsonLocation loc) throws IOException {
    try {
      return new SimpleDateFormat(DATE_FORMATTER).parse(text);
    } catch (ParseException e) {
      throw new JsonParseException("Could not parse date:" + text, loc, e);
    }
  }

  @Override
  public Date deserialize(JsonParser parser, DeserializationContext context) throws IOException {
    return getDate(parser.getText(), parser.getCurrentLocation());
  }
}
