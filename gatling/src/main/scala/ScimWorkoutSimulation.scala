import com.excilys.ebi.gatling.core.Predef._

import java.util.concurrent.ConcurrentLinkedQueue
import uaa.Config._

import uaa.ConstantFeeder
import uaa.RandomGroupMemberFeeder
import uaa.ScimApi._
import uaa._
import uaa.SequentialDisplayNameFeeder
import uaa.UsernamePasswordFeeder

/**
 * @author Luke Taylor
 * @author Vidya Valmikinathan
 */
class ScimWorkoutSimulation extends Simulation {
  val scimWorkout = scenario("SCIM USER workout")
    .exec(scimClientLogin())
    .repeat(nUsers) {
      bootstrap.feed(UsernamePasswordFeeder())
      .exec(findUserByName("username"))
      .exec(getUser)
//      .exec(updateUser)
    }

  val groupsWorkout = scenario("SCIM GROUP workout")
    .exec(scimClientLogin())
    .repeat(nUsers) { // basic lookups
      bootstrap.feed(SequentialDisplayNameFeeder())
      .exec(findGroupByName)
      .exec(getGroup)
      .exec(getMemberUser)
    }
    .repeat(nUsers - 1) { // repeatedly update the same group and make it grow gradually
      bootstrap.feed(RandomGroupMemberFeeder(users, 1))
      .exec(getMemberUser("memberName_1", "memberId"))
      .exec(addGroupMember("memberId"))
    }
    .repeat(1) { // prepare base for next part of workout
      bootstrap.feed(ConstantFeeder("displayName", "acme"))
      .exec(getMemberGroup("displayName", "memberId"))
    }
    .repeat(20) { // nest groups repeatedly
      bootstrap.feed(UniqueGroupFeeder(users, groups, 1))
      .exec(getMemberGroup("displayName", "groupId"))
      .exec(getGroup)
      .exec(nestGroup)
      .exec(findUserByName("memberName_1"))
      .exec(getGroup)
      .exec(addGroupMember("userId"))
      .exec(getUser)
      .exec((s: Session) => {
//        println("\n\n>>>>>> " + s.getAttribute("scimUser"))
        s})
    }


  def apply = {
    Seq(
      scimWorkout.configure users 1 protocolConfig uaaHttpConfig,
      groupsWorkout.configure users 1 protocolConfig uaaHttpConfig
    )
  }
}
