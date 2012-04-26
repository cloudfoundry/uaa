
import com.excilys.ebi.gatling.core.Predef._

import com.excilys.ebi.gatling.http.Predef._
import java.util.concurrent.TimeUnit
import uaa.Config._
import uaa.UsernamePasswordFeeder

import uaa.OAuthComponents._

class UaaSmokeSimulation extends Simulation {
  val Duration = sys.env.getOrElse("GATLING_DURATION", "60").toInt

  val authzCodeLogin = scenario("Authorization Code Login")
    .feed(UsernamePasswordFeeder())
    .loop(
      authorizationCodeLogin(appClient)
    .pause(0, 2)).during(Duration)


  val uiLoginLogout = scenario("UI Login/Logout")
    .feed(UsernamePasswordFeeder())
    .loop(
      chain.exec(login)
      .pause(0, 2000, TimeUnit.MILLISECONDS)
      .insertChain(logout)
    ).during(Duration)

  val vmcUserLogins = scenario("VMC Login")
    .loop(
      chain.feed(UsernamePasswordFeeder())
    // Uses the session values for username/password provided by the feeder
        .exec(vmcLogin())
        .pause(0, 2000, TimeUnit.MILLISECONDS)
//        .exec((s: Session) => {println("User: %s, token: %s" format(s.getAttribute("username"), s.getAttribute("access_token"))); s})
    ).during(Duration)

  val passwordScores = scenario("Password score API")
    .loop(chain.exec(
      http("Check complex password")
      .post("/password")
      .param("password", "coRrecth0rseba++ery9.23.2007staple$")
      .check(status is 200, jsonPath("//score") is "10"))
      .exec(
      http("Check simple password")
        .post("/password")
        .param("password", "password1")
        .check(status is 200, jsonPath("//score") is "0"))
      .exec(
      http("Check adjacency password")
        .post("/password")
        .param("password", "sdfghhju")
        .check(status is 200, jsonPath("//score") is "1"))

  ).during(Duration)


  def apply = {
    Seq(
      uiLoginLogout.configure users 2 ramp 10 protocolConfig uaaHttpConfig,
      authzCodeLogin.configure users 2 ramp 10 protocolConfig uaaHttpConfig,
      passwordScores.configure users  2 protocolConfig uaaHttpConfig,
      vmcUserLogins.configure users 10 ramp 10 protocolConfig uaaHttpConfig
    )
  }
}
