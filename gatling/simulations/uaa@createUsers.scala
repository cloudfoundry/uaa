import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._
import com.excilys.ebi.gatling.script.GatlingSimulation
import java.util.concurrent.TimeUnit

import uaa._
import uaa.Config._
import uaa.ScimComponents._
import uaa.OAuthComponents._

class Simulation extends GatlingSimulation {

	val createUsers = scenario("Create user")
				.exec(clientCredentialsAccessTokenRequest(
								username = "scim",
								password = "scimsecret",
								client_id = "scim",
								scope = "write password")
				)
				.loop(
						chain.feed(UsernamePasswordFeeder())
						.insertChain(createScimUserChain)
						.pause(50,200, TimeUnit.MILLISECONDS)
				).times(10)

	runSimulation(createUsers.configure users 2 protocolConfig uaaHttpConfig)
}
