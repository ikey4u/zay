import Foundation

/// Progressive embedded rule-set stages for iOS Packet Tunnel.
///
/// - `0` core (no multi-MB `direct` / `reject`)
/// - `1` + `direct`
/// - `2` + `reject`
///
/// Cold start always uses stage 0. After TUN is up the extension walks upward.
/// If a stage jetsams the process, `attempting` is still set on the next start
/// and that stage is permanently capped (`failed`) so On-Demand cannot loop.
enum RulesProgress {
    static let maxStage = 2

    private static let maxOkKey = "rules.stage.maxOk"
    private static let attemptingKey = "rules.stage.attempting"
    private static let failedKey = "rules.stage.failed"

    /// Highest stage known to survive after reload.
    static var maxOk: Int {
        get { AppGroup.defaults.integer(forKey: maxOkKey) }
        set {
            AppGroup.defaults.set(min(max(newValue, 0), maxStage), forKey: maxOkKey)
            AppGroup.defaults.synchronize()
        }
    }

    /// Stage currently being probed; cleared only after a survival window.
    static var attempting: Int? {
        get {
            guard AppGroup.defaults.object(forKey: attemptingKey) != nil else { return nil }
            return AppGroup.defaults.integer(forKey: attemptingKey)
        }
        set {
            if let newValue {
                AppGroup.defaults.set(newValue, forKey: attemptingKey)
            } else {
                AppGroup.defaults.removeObject(forKey: attemptingKey)
            }
            AppGroup.defaults.synchronize()
        }
    }

    /// First stage that killed the extension (or failed reload). Never retry ≥ this.
    static var failed: Int? {
        get {
            guard AppGroup.defaults.object(forKey: failedKey) != nil else { return nil }
            return AppGroup.defaults.integer(forKey: failedKey)
        }
        set {
            if let newValue {
                AppGroup.defaults.set(newValue, forKey: failedKey)
            } else {
                AppGroup.defaults.removeObject(forKey: failedKey)
            }
            AppGroup.defaults.synchronize()
        }
    }

    static func profileString(_ stage: Int) -> String {
        String(min(max(stage, 0), maxStage))
    }

    /// If the previous probe never cleared `attempting`, treat it as jetsam/crash.
    static func absorbCrashIfNeeded() {
        guard let stage = attempting else { return }
        ZayLog.warn("rules stage \(stage) did not survive — marking failed")
        if failed.map({ stage < $0 }) ?? true {
            failed = stage
        }
        if maxOk >= stage {
            maxOk = max(0, stage - 1)
        }
        attempting = nil
    }

    /// Next stage to load after `current`, or nil when capped / done.
    static func nextCandidate(after current: Int) -> Int? {
        let next = current + 1
        guard next <= maxStage else { return nil }
        if let failed, next >= failed { return nil }
        return next
    }

    /// Whether a heavy set id is active at the given committed stage.
    static func includes(_ id: String, stage: Int) -> Bool {
        switch id {
        case "direct": return stage >= 1
        case "reject": return stage >= 2
        default: return true
        }
    }
}
