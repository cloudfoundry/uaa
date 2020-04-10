package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Arrays;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

/**
 * See https://tools.ietf.org/html/rfc7517
 */
public class JsonWebKeyDeserializer extends JsonDeserializer<JsonWebKey> {

  @Override
  public JsonWebKey deserialize(JsonParser p, DeserializationContext ctxt) {
    JsonNode node = JsonUtils.readTree(p);
    String kty = node.get("kty").asText("Unknown");
    if (Arrays.stream(JsonWebKey.KeyType.values())
        .noneMatch(knownKeyType -> knownKeyType.name().equals(kty))) {
      return null;
    }
    return new JsonWebKey(JsonUtils.getNodeAsMap(node));
  }
}
