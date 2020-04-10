package org.cloudfoundry.identity.uaa.oauth;

import static java.util.Optional.ofNullable;

import java.util.Date;
import org.cloudfoundry.identity.uaa.util.TimeService;
import org.joda.time.DateTime;

public class TokenValidityResolver {

  public static final int DEFAULT_TO_GLOBAL_POLICY = -1;
  private int globalTokenValiditySeconds;
  private TimeService timeService;
  private ClientTokenValidity clientTokenValidity;

  public TokenValidityResolver(
      ClientTokenValidity clientTokenValidity,
      int globalTokenValiditySeconds,
      TimeService timeService) {
    this.clientTokenValidity = clientTokenValidity;
    this.globalTokenValiditySeconds = globalTokenValiditySeconds;
    this.timeService = timeService;
  }

  public Date resolve(String clientId) {
    Integer tokenValiditySeconds =
        ofNullable(clientTokenValidity.getValiditySeconds(clientId))
            .orElse(clientTokenValidity.getZoneValiditySeconds());

    if (tokenValiditySeconds == DEFAULT_TO_GLOBAL_POLICY) {
      tokenValiditySeconds = globalTokenValiditySeconds;
    }

    return new DateTime(timeService.getCurrentTimeMillis())
        .plusSeconds(tokenValiditySeconds)
        .toDate();
  }

  public void setTimeService(TimeService timeService) {
    this.timeService = timeService;
  }
}
