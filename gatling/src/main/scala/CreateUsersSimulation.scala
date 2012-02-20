import com.excilys.ebi.gatling.app.Simulation
import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._

import uaa.Config._
import uaa.ScimComponents._

class CreateUsersSimulation extends Simulation {

	def apply = {
		val createUsers = scenario("Create users")
				.insertChain(createScimUsers(10))

		Seq(createUsers.configure users 5 protocolConfig uaaHttpConfig)
	}
}
