package org.cloudfoundry.identity.uaa.mfa;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import org.junit.Test;

public class GoogleMfaProviderConfigTest {

  GoogleMfaProviderConfig config;

  @Test
  public void testDefaultConfig() {
    config = new GoogleMfaProviderConfig();
    assertThat(config.getProviderDescription(), is(nullValue()));
    assertThat(config.getIssuer(), is(nullValue()));
  }
}
