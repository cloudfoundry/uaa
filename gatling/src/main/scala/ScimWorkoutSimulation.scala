import com.excilys.ebi.gatling.core.Predef._

import uaa.Config._

import uaa.ScimApi._
import uaa.UsernamePasswordFeeder

/**
 * @author Luke Taylor
 */
class ScimWorkoutSimulation extends Simulation {
  val scimWorkout = scenario("SCIM workout")
    .exec(scimClientLogin())
    .repeat(50) {
      bootstrap.feed(UsernamePasswordFeeder())
      .exec(findUserByName)
      .exec(getUser)
//      .exec(updateUser)
    }

  def apply = {
    Seq(
      scimWorkout.configure users 1 protocolConfig uaaHttpConfig
    )
  }
}
