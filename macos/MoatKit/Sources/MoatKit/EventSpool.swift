import Foundation

/// Bounded in-memory event ring with monotonic sequence numbers and explicit gap markers.
///
/// Enforcement never waits on the spool. When it overflows before a reader has caught up, or the extension
/// restarts, the hole is recorded as a `GapMarker` and shown in the app, rather than silently dropped.
public final class EventSpool: @unchecked Sendable {
    public let capacity: Int
    private let lock = NSLock()
    private var ring: [FlowRecord] = []
    private var nextSeq: UInt64
    private var readThrough: UInt64
    private var gapList: [GapMarker] = []

    /// - Parameter resumeAfter: the last sequence number a previous run handed out. When non-zero, the events of the
    ///   previous run that were never delivered are unrecoverable, and the restart is recorded as a gap.
    public init(capacity: Int, resumeAfter: UInt64 = 0, lastDeliveredBeforeRestart: UInt64 = 0) {
        self.capacity = max(1, capacity)
        nextSeq = resumeAfter + 1
        readThrough = resumeAfter
        if resumeAfter > lastDeliveredBeforeRestart {
            gapList.append(GapMarker(fromSeq: lastDeliveredBeforeRestart + 1, toSeq: resumeAfter, reason: "extension restarted before these events were delivered"))
        }
    }

    public var lastSeq: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return nextSeq - 1
    }

    public var gaps: [GapMarker] {
        lock.lock()
        defer { lock.unlock() }
        return gapList
    }

    @discardableResult
    public func append(facts: FlowFacts, decision: FlowDecision, measurement: Measurement) -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        let seq = nextSeq
        nextSeq += 1
        ring.append(FlowRecord(seq: seq, facts: facts, decision: decision, measurement: measurement))
        if ring.count > capacity {
            let dropped = ring.removeFirst()
            if dropped.seq > readThrough {
                // A reader never saw this event: that is a telemetry gap, extend or open one.
                if let last = gapList.last, last.toSeq + 1 == dropped.seq, last.reason == Self.overflow {
                    gapList[gapList.count - 1].toSeq = dropped.seq
                } else {
                    gapList.append(GapMarker(fromSeq: dropped.seq, toSeq: dropped.seq, reason: Self.overflow))
                }
                readThrough = dropped.seq
            }
        }
        return seq
    }

    static let overflow = "event spool overflowed before the app read these events"

    /// Newest first.
    public func recent(limit: Int) -> [FlowRecord] {
        lock.lock()
        defer { lock.unlock() }
        return Array(ring.suffix(max(0, limit)).reversed())
    }

    /// Events after `seq`, oldest first, and mark them delivered.
    public func drain(after seq: UInt64) -> (records: [FlowRecord], gap: GapMarker?) {
        lock.lock()
        defer { lock.unlock() }
        let out = ring.filter { $0.seq > seq }
        var gap: GapMarker?
        if let first = ring.first, seq + 1 < first.seq {
            gap = GapMarker(fromSeq: seq + 1, toSeq: first.seq - 1, reason: "events no longer held by the extension")
        }
        if let last = out.last { readThrough = max(readThrough, last.seq) }
        return (out, gap)
    }

    public func updateMeasurement(flowID: String, _ m: Measurement) {
        lock.lock()
        defer { lock.unlock() }
        if let i = ring.lastIndex(where: { $0.facts.id == flowID }) {
            ring[i].measurement = m
        }
    }
}
