import com.excilys.ebi.gatling.app.Gatling
import com.excilys.ebi.gatling.core.util.PathHelper.path2string
import com.excilys.ebi.gatling.app.Options

object Engine extends App {

	Gatling.start(Options(
		dataFolder = Some(IDEPathHelper.dataFolder),
		resultsFolder = Some(IDEPathHelper.resultsFolder),
		requestBodiesFolder = Some(IDEPathHelper.requestBodiesFolder),
		simulationBinariesFolder = Some(IDEPathHelper.mavenBinariesDir)))
}