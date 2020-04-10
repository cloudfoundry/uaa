package org.cloudfoundry.identity.uaa.account;

import java.sql.Timestamp;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.test.JsonTranslation;
import org.junit.jupiter.api.BeforeEach;

class ForgotPasswordInfoTest extends JsonTranslation<ForgotPasswordInfo> {

  @BeforeEach
  void setUp() {
    final ExpiringCode expiringCode =
        new ExpiringCode("code", new Timestamp(111111111L), "{}", "foo");

    final ForgotPasswordInfo forgotPasswordInfo = new ForgotPasswordInfo();
    forgotPasswordInfo.setUserId("aaaa");
    forgotPasswordInfo.setEmail("bbb@ccc.com");
    forgotPasswordInfo.setResetPasswordCode(expiringCode);

    super.setUp(forgotPasswordInfo, ForgotPasswordInfo.class);
  }
}
