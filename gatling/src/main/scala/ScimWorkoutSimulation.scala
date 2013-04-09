import com.excilys.ebi.gatling.core.Predef._
import com.excilys.ebi.gatling.http.Predef._

import uaa.Config._
import uaa.ScimApi._
import uaa._
import uaa.SequentialDisplayNameFeeder
import uaa.UsernamePasswordFeeder

import bootstrap._
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
    }
    .repeat(nUsers - 1) { // repeatedly update the same group and make it grow gradually
      feed(RandomGroupMemberFeeder(users, 1))
      .exec(findUserByName("memberName_1", "memberId"))
      .exec(addGroupMember("memberId"))
    }
    .repeat(1) { // prepare base for next part of workout
      feed(ConstantFeeder("displayName", "acme"))
      .exec(findGroupByName("displayName", "memberId"))
    }
    .repeat(20) { // nest groups repeatedly
      feed(UniqueGroupFeeder(users, groups, 1))
      .exec(findUserByName("displayName", "groupId"))
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

    setUp (
      scimWorkout.users(1).protocolConfig(uaaHttpConfig),
      groupsWorkout.users(1).protocolConfig(uaaHttpConfig)
    )
}
