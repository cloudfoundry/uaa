
import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._

import uaa.Config._
import uaa.ScimApi._
import uaa.UaaApi._
import uaa.OAuthComponents._
import uaa.{UniqueUsernamePasswordFeeder, User}

/**
 * @author Luke Taylor
 */
class UaaBaseDataCreationSimulation extends Simulation {
  val registerClients = scenario("Register clients")
    .exec(adminClientLogin())
    .doIf(haveAccessToken, chain.exec(
        registerClient(scimClient)
      )
      .exec(
        registerClient(appClient)
      )
    )

  def createUsers = scenario("Create users")
    .pause(5)
    .insertChain(createScimUsers(UniqueUsernamePasswordFeeder(users)))

  def apply = {
    Seq(
      registerClients.configure users 1 protocolConfig uaaHttpConfig,
      createUsers.configure users 5 protocolConfig uaaHttpConfig
    )
  }

}
