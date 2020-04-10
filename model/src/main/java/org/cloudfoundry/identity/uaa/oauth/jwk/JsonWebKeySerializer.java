package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.IOException;
import java.util.Map;

/**
 * See https://tools.ietf.org/html/rfc7517
 */
public class JsonWebKeySerializer extends JsonSerializer<JsonWebKey> {

  @Override
  public void serialize(JsonWebKey value, JsonGenerator gen, SerializerProvider serializers)
      throws IOException, JsonProcessingException {
    gen.writeStartObject();
    for (Map.Entry<String, Object> entry : value.getKeyProperties().entrySet()) {
      gen.writeFieldName(entry.getKey());
      gen.writeObject(entry.getValue());
    }
    gen.writeEndObject();
  }
}
