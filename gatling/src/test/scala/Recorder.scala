import com.excilys.ebi.gatling.core.util.PathHelper.path2string
import com.excilys.ebi.gatling.recorder.config.RecorderOptions
import com.excilys.ebi.gatling.recorder.controller.RecorderController

object Recorder extends App {

	RecorderController(new RecorderOptions(
		outputFolder = Some(IDEPathHelper.recorderOutputDirectory),
		simulationPackage = Some("org.test.gatling"),
		requestBodiesFolder = Some(IDEPathHelper.requestBodiesDirectory)))
}