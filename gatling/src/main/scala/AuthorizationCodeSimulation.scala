import com.excilys.ebi.gatling.app.Simulation
import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._

import uaa.OAuthComponents._
import uaa.Config._
import uaa.UsernamePasswordFeeder

class AuthorizationCodeSimulation extends Simulation {

  def apply = {
    val scn = scenario("Authorization Code Login")
      .feed(UsernamePasswordFeeder())
      .loop(
        // Uses the session values for username/password provided by the feeder
        authorizationCodeLogin()
          .pause(1, 2)).during(60)

    Seq(scn.configure users 10 ramp 10 protocolConfig uaaHttpConfig)
  }
}
