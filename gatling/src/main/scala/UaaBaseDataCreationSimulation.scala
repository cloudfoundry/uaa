
import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._

import uaa.Config._
import uaa.ScimComponents._

class UaaBaseDataCreationSimulation extends Simulation {
  val createUsers = scenario("Create users")
    .insertChain(createScimUsers(1000))

  def apply = {
    Seq(createUsers.configure users 1 protocolConfig uaaHttpConfig)
  }

}
