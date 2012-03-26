
import com.excilys.ebi.gatling.core.Predef._

import com.excilys.ebi.gatling.http.Predef._
import uaa.Config._
import uaa.UsernamePasswordFeeder

import uaa.OAuthComponents._

class UaaSmokeSimulation extends Simulation {
  val Duration = 60

  val vmcUserLogins = scenario("VMC Load Login")
    .loop(
      chain.feed(UsernamePasswordFeeder(resetAfter=1000))
    // Uses the session values for username/password provided by the feeder
        .exec(vmcLogin())
        .pause(0, 1)
//        .exec((s: Session) => {println("User: %s, token: %s" format(s.getAttribute("username"), s.getAttribute("access_token"))); s})
    ).during(Duration)


  def apply = {
    Seq(
      vmcUserLogins.configure users 100 ramp 10 protocolConfig uaaHttpConfig
    )
  }
}
