
import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._

import uaa.Config._
import uaa.ScimApi._
import uaa.UsernamePasswordFeeder
import bootstrap._

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
      exec(login)
      .pause(0, 2)
      .exec(logout)
  }

  val vmcLogins = scenario("CF Logins")
    .during(Duration) {
      feed(UsernamePasswordFeeder())
//        .exec(vmcLoginBadPassword())
        .exec(vmcLogin())
        .exec(vmcLogin())
//        .exec(vmcLoginBadUsername())
        .exec(vmcLogin())
        .exec(vmcLogin(username="shaun1", password="password"))
        .pause(0, 2)
  }

  val random = new scala.util.Random()

  val randomUserFeeder = new Feeder[String]() {
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
          .exec(findUserByName("username"))
          .exec(getUser)
          .pause(0, 2)
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
      .pause(1,5)
    }

  setUp(
       uiLoginLogout.users(2).ramp(10).protocolConfig(loginHttpConfig)
       , scimWorkout.users(3).ramp(10).protocolConfig(uaaHttpConfig)
       , authzCodeLogin.users(5).ramp(10).protocolConfig(loginHttpConfig)
       , passwordScores.users(1).ramp(10).protocolConfig(uaaHttpConfig)
       , vmcLogins.users(10).ramp(1).protocolConfig(uaaHttpConfig)
    )

}
