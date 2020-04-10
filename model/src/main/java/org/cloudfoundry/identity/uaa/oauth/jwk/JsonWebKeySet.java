package org.cloudfoundry.identity.uaa.oauth.jwk;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

/**
 * See https://tools.ietf.org/html/rfc7517
 */
public class JsonWebKeySet<T extends JsonWebKey> {

  private final List<T> keys;

  public JsonWebKeySet(@JsonProperty("keys") List<T> keys) {
    Set<T> set = new LinkedHashSet<>();
    // rules for how to override duplicates
    for (T key : keys) {
      if (key == null) {
        continue;
      }
      set.remove(key);
      set.add(key);
    }
    this.keys = new LinkedList(set);
  }

  public List<T> getKeys() {
    return Collections.unmodifiableList(keys);
  }
}
