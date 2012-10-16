
import com.excilys.ebi.gatling.core.Predef._

import com.excilys.ebi.gatling.http.Predef._
import java.util.concurrent.TimeUnit
import uaa.Config._
import uaa.ScimApi._
import uaa.{UniqueUsernamePasswordFeeder, User, UsernamePasswordFeeder}

import uaa.OAuthComponents._

class UaaSmokeSimulation extends Simulation {
  val Duration = sys.env.getOrElse("GATLING_DURATION", "600").toInt

  val authzCodeLogin = scenario("Authorization Code Login")
    .feed(UsernamePasswordFeeder())
    .during(Duration) {
      authorizationCodeLogin(appClient)
      .pause(0, 2)
    }

  val uiLoginLogout = scenario("UI Login/Logout")
    .feed(UsernamePasswordFeeder())
    .during(Duration) {
      chain.exec(login)
      .pause(0, 2000, TimeUnit.MILLISECONDS)
      .insertChain(logout)
  }

  val vmcUserLogins = scenario("VMC Login")
    .during(Duration) {
      chain.feed(UsernamePasswordFeeder())
    // Uses the session values for username/password provided by the feeder
        .exec(vmcLogin())
        .pause(0, 2000, TimeUnit.MILLISECONDS)
//        .exec((s: Session) => {println("User: %s, token: %s" format(s.getAttribute("username"), s.getAttribute("access_token"))); s})
    }

  val random = new scala.util.Random()

  val randomUserFeeder = new Feeder() {
    def hasNext = true
    def next() = Map("username" -> ("randy_" + random.nextLong()), "password" -> "password")
  }

  import bootstrap._

  val scimWorkout = scenario("SCIM workout")
    .exec(scimClientLogin())
    .doIf(haveAccessToken) {
       during(Duration) {
         feed(randomUserFeeder)
          .exec(createUser)
          .exec(findUserByName)
          .exec(getUser)
          .pause(0, 2000, TimeUnit.MILLISECONDS)
       }
    }

  val passwordScores = scenario("Password score API")
    .during(Duration) {
      bootstrap.exec(
       http("Check complex password")
      .post("/password/score")
      .param("password", "coRrecth0rseba++ery9.23.2007staple$")
      .check(status is 200, jsonPath("//score") is "10"))
      .exec(
      http("Check simple password")
        .post("/password/score")
        .param("password", "password1")
        .check(status is 200, jsonPath("//score") is "0"))
      .exec(
      http("Check adjacency password")
        .post("/password/score")
        .param("password", "sdfghhju")
        .check(status is 200, jsonPath("//score") is "1"))
    }


  def apply = {
    Seq(
       uiLoginLogout.configure users 2 ramp 10 protocolConfig loginHttpConfig
       , scimWorkout.configure users 10 ramp 10 protocolConfig uaaHttpConfig
       , authzCodeLogin.configure users 5 ramp 10 protocolConfig loginHttpConfig
       , passwordScores.configure users 1 ramp 10 protocolConfig uaaHttpConfig
       , vmcUserLogins.configure users 10 ramp 10 protocolConfig uaaHttpConfig
    )
  }
}
