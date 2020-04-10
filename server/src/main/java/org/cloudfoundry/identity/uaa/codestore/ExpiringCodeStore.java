package org.cloudfoundry.identity.uaa.codestore;

import java.sql.Timestamp;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

public interface ExpiringCodeStore {

  /**
   * Generate and persist a one-time code with an expiry date.
   *
   * @param data JSON object to be associated with the code
   * @param intent An optional key (not necessarily unique) for looking up codes
   * @return code the generated one-time code
   * @throws java.lang.NullPointerException if data or expiresAt is null
   * @throws java.lang.IllegalArgumentException if expiresAt is in the past
   */
  ExpiringCode generateCode(String data, Timestamp expiresAt, String intent, String zoneId);

  /**
   * Retrieve a code and delete it if it exists.
   *
   * @param code the one-time code to look for
   * @return code or null if the code is not found
   * @throws java.lang.NullPointerException if the code is null
   */
  ExpiringCode retrieveCode(String code, String zoneId);

  /**
   * Set the code generator for this store.
   *
   * @param generator Code generator
   */
  void setGenerator(RandomValueStringGenerator generator);

  /**
   * Remove all codes matching a given intent.
   *
   * @param intent Intent of codes to remove
   */
  void expireByIntent(String intent, String zoneId);
}
