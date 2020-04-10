package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.core.type.TypeReference;
import java.util.Collections;
import org.cloudfoundry.identity.uaa.util.JsonUtils;

public class JsonWebKeyHelper {

  public static JsonWebKeySet<JsonWebKey> deserialize(String s) {
    if (!s.contains("\"keys\"")) {
      return new JsonWebKeySet<>(
          Collections.singletonList(JsonUtils.readValue(s, JsonWebKey.class)));
    } else {
      return JsonUtils.readValue(s, new TypeReference<JsonWebKeySet<JsonWebKey>>() {});
    }
  }
}
