import Foundation
import CoreServices

let args = Array(CommandLine.arguments.dropFirst())
let diagnosticID = "local.szu.securelink.casdiagnostic"
func current() -> String? { LSCopyDefaultHandlerForURLScheme("securelink" as CFString)?.takeRetainedValue() as String? }
func fail(_ text: String) -> Never { fputs(text + "\n", stderr); exit(1) }
guard let action = args.first else { fail("Expected status, record, activate or restore") }
if action == "status", args.count == 1 {
    print(current() ?? "unassigned")
    exit(0)
}
guard args.count == 3, args[1] == "--allow-protocol-change", ["record", "activate", "restore"].contains(action) else { fail("Protocol changes require explicit --allow-protocol-change and backup path") }
let backup = URL(fileURLWithPath: args[2])
func valid(_ value: String) -> Bool {
    !value.isEmpty && value.count <= 255 && value.unicodeScalars.allSatisfy { CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-").contains($0) }
}
let original: String
if action == "record" {
    guard !FileManager.default.fileExists(atPath: backup.path) else { fail("Backup already exists; restore it before another activation") }
    guard let existing = current(), valid(existing), existing != diagnosticID else { fail("Cannot safely determine the original handler") }
    original = existing
    let data = try JSONSerialization.data(withJSONObject: ["originalHandler": original])
    try data.write(to: backup, options: [.withoutOverwriting])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backup.path)
    print("original-handler-recorded")
    exit(0)
} else {
    let values = try JSONSerialization.jsonObject(with: Data(contentsOf: backup)) as? [String: String]
    guard let saved = values?["originalHandler"], valid(saved), saved != diagnosticID else { fail("Invalid restoration record") }
    original = saved
}
if action == "activate", current() != original { fail("Handler changed since recording; restore before proceeding") }
let target = action == "activate" ? diagnosticID : original
let result = LSSetDefaultHandlerForURLScheme("securelink" as CFString, target as CFString)
guard result == noErr, current() == target else {
    if action == "activate" { _ = LSSetDefaultHandlerForURLScheme("securelink" as CFString, original as CFString) }
    fail("Handler change not confirmed; backup retained for restoration")
}
print(action == "activate" ? "diagnostic-handler-active" : "original-handler-restored")
// Keep the backup for repeatable restoration and audit; never discard it automatically.
