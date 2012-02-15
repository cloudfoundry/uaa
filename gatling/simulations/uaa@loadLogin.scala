import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._
import com.excilys.ebi.gatling.script.GatlingSimulation

import uaa.OAuthComponents._
import uaa.Config._
import uaa.UsernamePasswordFeeder

class Simulation extends GatlingSimulation {

	val scn = scenario("VMC Load Login")
		.feed(UsernamePasswordFeeder())
		.loop(
				chain.exec(
				// Uses the session values for username/password provided by the feeder
					vmcLogin ()
				)
				.pause(1,2)
		).during(60)


	runSimulation(scn.configure users 10 ramp 10 protocolConfig uaaHttpConfig)
}
