package org.cloudfoundry.identity.uaa.oauth.jwt;

import org.cloudfoundry.identity.uaa.oauth.KeyInfo;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoBuilder;
import org.junit.Before;
import org.junit.Test;

import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertNull;

public class JwtHelperX5tTest {
  public static final String SIGNING_KEY_1 = "-----BEGIN RSA PRIVATE KEY-----\n" +
      "MIIBOQIBAAJAcPh8sj6TdTGYUTAn7ywyqNuzPD8pNtmSFVm87yCIhKDdIdEQ+g8H\n" +
      "xq8zBWtMN9uaxyEomLXycgTbnduW6YOpyQIDAQABAkAE2qiBAC9V2cuxsWAF5uBG\n" +
      "YSpSbGRY9wBP6oszuzIigLgWwxYwqGSS/Euovn1/BZEQL1JLc8tRp+Zn34JfLrAB\n" +
      "AiEAz956b8BHk2Inbp2FcOvJZI4XVEah5ITY+vTvYFTQEz0CIQCLIN4t+ehu/qIS\n" +
      "fj94nT9LhKPJKMwqhZslC0tIJ4OpfQIhAKaruHhKMBnYpc1nuEsmg8CAvevxBnX4\n" +
      "nxH5usX+uyfxAiA0l7olWyEYRD10DDFmINs6auuXMUrskBDz0e8lWXqV6QIgJSkM\n" +
      "L5WgVmzexrNmKxmGQQhNzfgO0Lk7o+iNNZXbkxw=\n" +
      "-----END RSA PRIVATE KEY-----";
  public static final String CERTIFICATE_1 = "-----BEGIN CERTIFICATE-----\n" +
      "MIIC6TCCAlICCQDN85uMN+4K5jANBgkqhkiG9w0BAQsFADCBuDELMAkGA1UEBhMC\n" +
      "VVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1TYW4gRnJhbmNpc2NvMR0wGwYDVQQK\n" +
      "DBRQaXZvdGFsIFNvZnR3YXJlIEluYzEeMBwGA1UECwwVQ2xvdWRmb3VuZHJ5IElk\n" +
      "ZW50aXR5MRswGQYDVQQDDBJ1YWEucnVuLnBpdm90YWwuaW8xKDAmBgkqhkiG9w0B\n" +
      "CQEWGXZjYXAtZGV2QGNsb3VkZm91bmRyeS5vcmcwHhcNMTUwMzAyMTQyMDQ4WhcN\n" +
      "MjUwMjI3MTQyMDQ4WjCBuDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRYwFAYD\n" +
      "VQQHDA1TYW4gRnJhbmNpc2NvMR0wGwYDVQQKDBRQaXZvdGFsIFNvZnR3YXJlIElu\n" +
      "YzEeMBwGA1UECwwVQ2xvdWRmb3VuZHJ5IElkZW50aXR5MRswGQYDVQQDDBJ1YWEu\n" +
      "cnVuLnBpdm90YWwuaW8xKDAmBgkqhkiG9w0BCQEWGXZjYXAtZGV2QGNsb3VkZm91\n" +
      "bmRyeS5vcmcwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN0u5J4BJUDgRv6I\n" +
      "h5/r7rZjSrFVLL7bl71CzBIaVk1BQPYfBC8gggGAWmYYxJV0Kz+2Vx0Z96OnXhJk\n" +
      "gG46Zo2KMDudEeSdXou+dSBNISDv4VpLKUGnVU4n/L0khbI+jX51aS80ub8vThca\n" +
      "bkdY5x4Ir8G3QCQvCGKgU2emfFe7AgMBAAEwDQYJKoZIhvcNAQELBQADgYEAXghg\n" +
      "PwMhO0+dASJ83e2Bu63pKO808BrVjD51sSEMb0qwFc5IV6RzK/mkJgO0fphhoqOm\n" +
      "ZLzGcSYwCmj0Vc0GO5NgnFVZg4N9CyYCpDMeQynumlrNhRgnZRzlqXtQgL2bQDiu\n" +
      "coxNL/KY05iVlE1bmq/fzNEmEi2zf3dQV8CNSYs=\n" +
      "-----END CERTIFICATE-----";

  private KeyInfo keyInfo;

  @Before
  public void setUp() {
    keyInfo = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", CERTIFICATE_1);
  }

  @Test
  public void jwtHeaderShouldContainX5tInTheHeader() {
    Jwt jwt = JwtHelper.encodePlusX5t("testJwtContent", keyInfo, keyInfo.verifierCertificate());
    assertThat("ijN2hCBB85pSpHSUQGBLK2xGurY", is(jwt.getHeader().getX5t()));
  }

  @Test
  public void jwtHeaderMustNotContainJkuInTheHeader() {
    Jwt jwt = JwtHelper.encodePlusX5t("testJwtContent", keyInfo, keyInfo.verifierCertificate());
    assertThat(jwt.getHeader().getX5t(), is("ijN2hCBB85pSpHSUQGBLK2xGurY"));
    assertNull(jwt.getHeader().getJku());
  }

  @Test
  public void jwtKeysMustNotContainX5t() {
    Map<String, Object> keys = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", "test")
        .getJwkMap();
    assertNull(keys.get("x5t"));
  }

  @Test
  public void jwtKeysShouldContainX5t() {
    Map<String, Object> keys = keyInfo.getJwkMap();
    assertThat(keys.get("x5t"), is("ijN2hCBB85pSpHSUQGBLK2xGurY"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void jwtHeaderShouldFailWithInvalidCert() {
    KeyInfo keyInfo1 = KeyInfoBuilder.build("testKid", SIGNING_KEY_1, "http://localhost/uaa", "RS256", "X");
    JwtHelper.encodePlusX5t("testJwtContent", keyInfo1, keyInfo1.verifierCertificate());
  }

  @Test(expected = IllegalArgumentException.class)
  public void getX509CertThumbprintInvalidAlg() {
    JwtHelper.getX509CertThumbprint("test".getBytes(), "unknown");
  }
}
