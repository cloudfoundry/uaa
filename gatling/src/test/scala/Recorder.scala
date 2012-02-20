import com.excilys.ebi.gatling.core.util.PathHelper.path2string
import com.excilys.ebi.gatling.recorder.ui.GatlingHttpProxyUI

import IDEPathHelper.recorderOutputFolder
import IDEPathHelper.requestBodiesFolder

object Recorder extends App {

	GatlingHttpProxyUI.main(Array("-of", recorderOutputFolder, "-run", "-ide", "", "-bf", requestBodiesFolder))
}