
import com.excilys.ebi.gatling.core.Predef._

import com.excilys.ebi.gatling.http.Predef._
import uaa.Config._
import uaa.UsernamePasswordFeeder

import uaa.OAuthComponents._

class AuthCodeFlowSimulation extends Simulation {

    setUp(
      scenario("Authorization Code Login")
        .feed(UsernamePasswordFeeder())
        .exec(
          authorizationCodeLogin(appClient)).users(1).protocolConfig(uaaHttpConfig)
    )

}
