**SECURITY NOTICE: If you have found a security problem in the UAA, please do not file a public github issue. Instead, please send an email to security@cloudfoundry.org**

Thanks for taking the time to file an issue. You'll minimize back and forth and help us help you more effectively by answering all of the following questions as specifically and completely as you can.

### What version of UAA are you running?

What output do you see from `curl <YOUR_UAA>/info -H'Accept: application/json'`?


### How are you deploying the UAA?

I am deploying the UAA

- locally only using gradlew
- using a bosh release I downloaded from bosh.io
- using cf-release
- using cf-deployment
- as part of a commercial Cloud Foundry distribution
- other (please explain)


### What did you do?

If possible, provide a recipe for reproducing the error. Exact `curl` or `uaac` commands with verbose output are helpful. If your problem is configuration-related, please include portions of your uaa.yml or bosh deployment manifest that you believe may be relevant (but do not divulge secrets!)


### What did you expect to see? What goal are you trying to achieve with the UAA?


### What did you see instead?

Please include UAA logs if available.
