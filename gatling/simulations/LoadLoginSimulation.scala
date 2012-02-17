import com.excilys.ebi.gatling.app.Simulation
import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._

import uaa.OAuthComponents._
import uaa.Config._
import uaa.UsernamePasswordFeeder

class LoadLoginSimulation extends Simulation {

	def apply = {
		val scn = scenario("VMC Load Login")
			.feed(UsernamePasswordFeeder())
			.loop(
					chain.exec(
					// Uses the session values for username/password provided by the feeder
						vmcLogin ()
					)
					.pause(1,2)
			).during(60)

		Seq(scn.configure users 10 ramp 10 protocolConfig uaaHttpConfig)
	}
}
