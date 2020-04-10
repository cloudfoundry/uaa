package org.cloudfoundry.identity.uaa.impl;

import static org.cloudfoundry.identity.uaa.impl.JsonDateDeserializer.DATE_FORMATTER;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

/** JSON serializer for Jackson to handle regular date instances as timestamps in ISO format. */
public class JsonDateSerializer extends JsonSerializer<Date> {

  @Override
  public void serialize(Date date, JsonGenerator generator, SerializerProvider provider)
      throws IOException {
    String formatted = new SimpleDateFormat(DATE_FORMATTER).format(date);
    generator.writeString(formatted);
  }
}
