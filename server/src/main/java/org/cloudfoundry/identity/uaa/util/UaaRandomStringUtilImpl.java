package org.cloudfoundry.identity.uaa.util;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.stereotype.Component;

@Component
public class UaaRandomStringUtilImpl implements UaaRandomStringUtil {

  private static final char[] CHARS =
      "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();

  private final SecureRandom secureRandom;

  public UaaRandomStringUtilImpl() throws NoSuchProviderException, NoSuchAlgorithmException {
    secureRandom = SecureRandom.getInstance("SHA1PRNG", "SUN");
    secureRandom.setSeed(secureRandom.generateSeed(1024));
  }

  @Override
  public String getSecureRandom(final int length) {
    return RandomStringUtils.random(length, 0, CHARS.length, true, true, CHARS, secureRandom);
  }
}
