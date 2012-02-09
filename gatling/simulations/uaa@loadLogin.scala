import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.core.feeder.Feeder
import com.excilys.ebi.gatling.http.Predef._
import com.excilys.ebi.gatling.script.GatlingSimulation

class Simulation extends GatlingSimulation {

  val urlBase = sys.env.getOrElse("GATLING_UAA_BASE", "http://localhost:8080/uaa")

  val httpConf = httpConfig.baseURL(urlBase)

  val plainHeaders = Map(
    "Accept" -> "application/json",
    "Content-Type" -> "application/x-www-form-urlencoded")

  val feeder = new Feeder {
    var counter = 0
    def next = {
      println("Counter " + counter)
      counter += 1
      Map("username" -> ("joe" + counter))
    }
  }

  val scn = scenario("Scenario name")
    .feed(feeder)
    .loop(
      chain
        .exec(
          http("login")
            .post("/oauth/authorize")
            .param("client_id", "vmc")
            .param("scope", "read")
            .param("credentials", """{"username":"${username}","password":"koala"}""")
            .param("redirect_uri", "uri:oauth:token")
            .param("response_type", "token")
            .headers(plainHeaders)
            .check(status.is(302)))).times(200)

  runSimulation(scn.configure users 10 protocolConfig httpConf)
}
