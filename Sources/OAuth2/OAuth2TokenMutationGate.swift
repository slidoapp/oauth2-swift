import Foundation

/// Cancellation-aware asynchronous gate for token-endpoint operations that may rotate credential state.
actor OAuth2TokenMutationGate {
	private struct Waiter {
		let id: UUID
		let continuation: CheckedContinuation<Void, any Error>
	}

	private var isLocked = false
	private var waiters = [Waiter]()

	func withPermit<T: Sendable>(
		_ operation: @escaping @Sendable () async throws -> T
	) async throws -> T {
		try await acquire()
		defer { release() }
		try Task.checkCancellation()
		return try await operation()
	}

	private func acquire() async throws {
		let waiterID = UUID()
		try await withTaskCancellationHandler {
			try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
				if Task.isCancelled {
					continuation.resume(throwing: CancellationError())
				}
				else if !isLocked {
					isLocked = true
					continuation.resume()
				}
				else {
					waiters.append(Waiter(id: waiterID, continuation: continuation))
				}
			}
		} onCancel: {
			Task {
				await self.cancelWaiter(waiterID)
			}
		}
	}

	private func release() {
		if waiters.isEmpty {
			isLocked = false
		}
		else {
			let waiter = waiters.removeFirst()
			waiter.continuation.resume()
		}
	}

	private func cancelWaiter(_ waiterID: UUID) {
		guard let index = waiters.firstIndex(where: { $0.id == waiterID }) else { return }
		let waiter = waiters.remove(at: index)
		waiter.continuation.resume(throwing: CancellationError())
	}
}
