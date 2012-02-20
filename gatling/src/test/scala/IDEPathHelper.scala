import scala.tools.nsc.io.File
import scala.tools.nsc.io.Path
object IDEPathHelper {

	val gatlingConfUrl = getClass.getClassLoader.getResource("gatling.conf").getPath
	val projectRootDir = File(gatlingConfUrl).parents(2)

	val mavenSourcesDir = projectRootDir / "src" / "main" / "scala"
	val mavenResourcesDir = projectRootDir / "src" / "main" / "resources"
	val mavenTargetDir = projectRootDir / "target"
	val mavenBinariesDir = mavenTargetDir / "classes"

	val dataFolder = mavenResourcesDir / "data"
	val requestBodiesFolder = mavenResourcesDir / "request-bodies"

	val recorderOutputFolder = mavenSourcesDir / Path("${package}".split("."))
	val resultsFolder = mavenTargetDir / "gatling-results"
}