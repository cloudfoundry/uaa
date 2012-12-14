
import com.excilys.ebi.gatling.core.Predef._

import com.excilys.ebi.gatling.http.Predef._
import java.util.concurrent.TimeUnit
import uaa.Config._
import uaa.ScimApi._
import uaa.{ UniqueUsernamePasswordFeeder, User, UsernamePasswordFeeder }

import uaa.OAuthComponents._

class AuthCodeFlowSimulation extends Simulation {

  def apply = {
    Seq(
      scenario("Authorization Code Login")
        .feed(UsernamePasswordFeeder())
        .exec(
          authorizationCodeLogin(appClient)).configure users 1 protocolConfig uaaHttpConfig)
  }

}
