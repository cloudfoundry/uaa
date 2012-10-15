package uaa

import com.excilys.ebi.gatling.core.feeder.Feeder
import java.util.concurrent.ConcurrentLinkedQueue

import collection.JavaConversions._

/**
 * User feeder which only supplies each user once.
 */
case class UniqueUsernamePasswordFeeder(usrs: Seq[User], password: Option[String] = None) extends Feeder {
  private val users = new ConcurrentLinkedQueue[User](usrs)

  println("%d users".format(users.size()))

  def next = {
    val user = users.remove()
    val pass = password match { case None => user.password; case Some(p) => p}
    Map("username" -> user.username, "password" -> pass)
  }

  def hasNext = !users.isEmpty
}
