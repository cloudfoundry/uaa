
import com.excilys.ebi.gatling.core.Predef._

import com.excilys.ebi.gatling.http.Predef._
import uaa.Config._

/**
 * Scenarios which hit /varz and /healthz.
 *
 * Also useful for retrieving remote heap information without any effort
 */
class VarzSimulation extends Simulation {
  val Duration = 60

  def varzScenario(duration: Int = 60) = scenario("Varz")
    .loop(
      chain.exec(
        http("Varz")
        .get("/varz")
        .basicAuth(varz_client_id, varz_client_secret)
        .asJSON
        .check(status is 200, jsonPath("/memory/heap_memory_usage").saveAs("heap"))
       ).exec((s:Session) => {
        println("Remote heap information: %s".format(s.getAttribute("heap")));
        s
        }
      ).pause(5)
       .exec(
        http("Healthz")
          .get("/healthz")
          .basicAuth(varz_client_id, varz_client_secret)
          .check(status is 200)
      )
    ).during(duration)

  def apply() = Seq (varzScenario(Duration).configure users 50 ramp 10 protocolConfig uaaHttpConfig )
}
