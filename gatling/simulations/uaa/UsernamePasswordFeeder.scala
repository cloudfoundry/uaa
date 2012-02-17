package uaa

import com.excilys.ebi.gatling.core.feeder.Feeder

/**
 * Counter-based username generator with fixed password, defaulting to "password".
 */
case class UsernamePasswordFeeder(prefix: String = "joe", password: String = "password") extends Feeder {
	var counter = 0

	def next = {
		counter += 1
		Map("username" -> (prefix + counter), "password" -> password)
	}
}
