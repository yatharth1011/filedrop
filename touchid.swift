// Touch ID prompt for CodeGate (compiled by install.sh into ./touchid).
//
//   touchid check           exit 0 if Touch ID can be used right now, 2 if not
//   touchid prompt <reason> shows the system Touch ID dialog on this Mac;
//                           exit 0 = verified, 1 = declined/failed,
//                           2 = unavailable, 3 = timed out
//
// Biometrics only (no "use password" button in the dialog): the password
// fallback is handled by CodeGate's own login page instead.
import Foundation
import LocalAuthentication

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
let args = CommandLine.arguments
let context = LAContext()
context.localizedFallbackTitle = ""

var availabilityError: NSError?
let available = context.canEvaluatePolicy(policy, error: &availabilityError)

guard args.count >= 2 else { exit(64) }

switch args[1] {
case "check":
    exit(available ? 0 : 2)
case "prompt" where args.count >= 3:
    guard available else { exit(2) }
    let done = DispatchSemaphore(value: 0)
    var verified = false
    context.evaluatePolicy(policy, localizedReason: args[2]) { success, _ in
        verified = success
        done.signal()
    }
    if done.wait(timeout: .now() + 45) == .timedOut {
        context.invalidate()
        exit(3)
    }
    exit(verified ? 0 : 1)
default:
    exit(64)
}
