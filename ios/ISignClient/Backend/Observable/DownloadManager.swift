//
//  enum.swift
//  Feather
//
//  Created by samara on 3.05.2025.
//

import Foundation
import Combine
import UIKit.UIImpactFeedbackGenerator
import BackgroundTasks

class Download: Identifiable, @unchecked Sendable {
	@Published var progress: Double = 0.0
	@Published var bytesDownloaded: Int64 = 0
	@Published var totalBytes: Int64 = 0
	@Published var unpackageProgress: Double = 0.0
	
	var overallProgress: Double {
		onlyArchiving
		? unpackageProgress
		: (0.3 * unpackageProgress) + (0.7 * progress)
	}
	
	var task: URLSessionDownloadTask?
	var resumeData: Data?
    var managedPolicy: ISignDownloadPolicy?
    var managedGeneration: UUID?
    var managedResolution: Task<Void, Never>?
    var managedRetries = 0
    var isManaged: Bool { url.scheme == "isign-feather" }
	
	let id: String
	let url: URL
	let fileName: String
	let onlyArchiving: Bool
	var sourceProvenance: SourceAppProvenance?
	
	init(
		id: String,
		url: URL,
		onlyArchiving: Bool = false,
		sourceProvenance: SourceAppProvenance? = nil
	) {
		self.id = id
		self.url = url
		self.onlyArchiving = onlyArchiving
		self.sourceProvenance = sourceProvenance
		self.fileName = url.lastPathComponent
	}
}

class DownloadManager: NSObject, ObservableObject {
	static let shared = DownloadManager()
	
	@Published var downloads: [Download] = []
	
	var manualDownloads: [Download] {
		downloads.filter { isManualDownload($0.id) }
	}
	
	private var _session: URLSession!
	
	#if !targetEnvironment(macCatalyst)
	private func _updateBackgroundAudioState() {
		if #unavailable(iOS 26.0){
			if !downloads.isEmpty {
				BackgroundAudioManager.shared.start()
			} else  {
				BackgroundAudioManager.shared.stop()
			}
		}
	}
	#endif
	
	override init() {
		super.init()
		let configuration = URLSessionConfiguration.default
		_session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
	}
	
	func startDownload(
		from url: URL,
		id: String = UUID().uuidString,
		sourceProvenance: SourceAppProvenance? = nil
	) -> Download {
		let requestHasSourceProvenance = sourceProvenance != nil
		if let existingDownload = downloads.first(where: {
			$0.url == url && ($0.sourceProvenance != nil) == requestHasSourceProvenance
		}) {
			resumeDownload(existingDownload)
			return existingDownload
		}
		
		let download = Download(id: id, url: url, sourceProvenance: sourceProvenance)
		
        downloads.append(download)
        if download.isManaged {
            resolveManaged(download)
        } else {
            let task = _session.downloadTask(with: url)
            download.task = task
            task.resume()
        }
		
		#if !targetEnvironment(macCatalyst)
		if #available(iOS 26.0, *) {
			BackgroundTaskManager.shared.startTask(for: id, filename: url.lastPathComponent)
		} else {
			_updateBackgroundAudioState()
		}
		#endif
		
		return download
	}
	
	func startArchive(
		from url: URL,
		id: String = UUID().uuidString
	) -> Download {
		let download = Download(id: id, url: url, onlyArchiving: true)
		downloads.append(download)
		
		#if !targetEnvironment(macCatalyst)
		_updateBackgroundAudioState()
		#endif
		
		return download
	}
	
	func resumeDownload(_ download: Download) {
        if download.isManaged { download.task?.cancel(); download.resumeData = nil; resolveManaged(download); return }
		if let resumeData = download.resumeData {
			let task = _session.downloadTask(withResumeData: resumeData)
			download.task = task
			task.resume()
			
			#if !targetEnvironment(macCatalyst)
			_updateBackgroundAudioState()
			#endif
		} else if let url = download.task?.originalRequest?.url {
			let task = _session.downloadTask(with: url)
			download.task = task
			task.resume()
			
			#if !targetEnvironment(macCatalyst)
			_updateBackgroundAudioState()
			#endif
		}
	}
	
	func cancelDownload(_ download: Download) {
        download.managedResolution?.cancel()
		download.task?.cancel()
		
		if let index = downloads.firstIndex(where: { $0.id == download.id }) {
			downloads.remove(at: index)
			
			#if !targetEnvironment(macCatalyst)
			_updateBackgroundAudioState()

			if #available(iOS 26.0, *) {
				BackgroundTaskManager.shared.stopTask(for: download.id, success: false)
			}
			#endif
		}
	}
	
    func cancelManagedDownloads() {
        for download in downloads.filter(\.isManaged) { cancelDownload(download) }
    }

    private func resolveManaged(_ download: Download) {
        download.managedResolution?.cancel()
        download.managedResolution = Task { @MainActor in
            do {
                let client = try ISignStore.shared.requireClient()
                let stamp = client.generation
                if let original = download.managedGeneration, original != stamp { throw ISignFailure(code: "STALE_SESSION") }
                download.managedGeneration = stamp
                let descriptor = try await ISignStore.shared.descriptor(download.url)
                try client.check(stamp); try Task.checkCancellation()
                guard self.downloads.contains(where: { $0 === download }) else { return }
                download.managedPolicy = try ISignDownloadPolicy(descriptor.url)
                // Descriptor has no bearer or publisher-auth headers. Session defaults stay unchanged.
                let task = self._session.downloadTask(with: descriptor.url)
                download.task = task; task.resume()
            } catch {
                guard !Task.isCancelled else { return }
                self.cancelDownload(download)
                ISignStore.shared.error = error.localizedDescription
                UIAlertController.showAlertWithOk(title: .localized("Download Failed"), message: error.localizedDescription)
            }
        }
    }

    private func retryManaged(_ download: Download) {
        guard download.managedRetries < 1 else {
            cancelDownload(download)
            Task { @MainActor in
                ISignStore.shared.error = ISignFailure(code: "MANAGED_DOWNLOAD_FAILED").localizedDescription
                UIAlertController.showAlertWithOk(title: .localized("Download Failed"), message: .localized("The managed download failed. Refresh this source and try again."))
            }
            return
        }
        download.managedRetries += 1
        resolveManaged(download)
    }

	func isManualDownload(_ string: String) -> Bool {
		return string.contains("FeatherManualDownload")
	}
	
	func getDownload(by id: String) -> Download? {
		return downloads.first(where: { $0.id == id })
	}
	
	func getDownloadIndex(by id: String) -> Int? {
		return downloads.firstIndex(where: { $0.id == id })
	}
	
	func getDownloadTask(by task: URLSessionDownloadTask) -> Download? {
		return downloads.first(where: { $0.task == task })
	}
}

extension DownloadManager: URLSessionDownloadDelegate {
	
	func handlePachageFile(url: URL, dl: Download) throws {
		FR.handlePackageFile(url, download: dl) { err in
			if err != nil {
				let generator = UINotificationFeedbackGenerator()
				generator.notificationOccurred(.error)
			}
			
			DispatchQueue.main.async {
				if let index = DownloadManager.shared.getDownloadIndex(by: dl.id) {
					DownloadManager.shared.downloads.remove(at: index)
					
					#if !targetEnvironment(macCatalyst)
					if #available(iOS 26.0, *) {
						BackgroundTaskManager.shared.updateProgress(for: dl.id, progress: 1.0)
					}
					
					self._updateBackgroundAudioState()
					#endif
				}
			}
		}
	}
	
	func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        guard let download = getDownloadTask(by: downloadTask) else { return }
        if download.isManaged {
            guard let response = downloadTask.response as? HTTPURLResponse,
                  (200..<300).contains(response.statusCode), let url = response.url,
                  download.managedPolicy?.allows(url) == true else {
                DispatchQueue.main.async { self.retryManaged(download) }
                return
            }
        }

		let tempDirectory = FileManager.default.temporaryDirectory
		let customTempDir = tempDirectory.appendingPathComponent("FeatherDownloads", isDirectory: true)
		
		do {
			try FileManager.default.createDirectoryIfNeeded(at: customTempDir)
			
			// Use the server-suggested filename if available, otherwise fallback
			let suggestedFileName = URL(fileURLWithPath: downloadTask.response?.suggestedFilename ?? (download.isManaged ? "iSign-download.ipa" : download.fileName)).lastPathComponent
			let packageName = download.isManaged ? ISignDownloadPolicy.packageFilename(suggestedFileName) : suggestedFileName
            let destinationURL = customTempDir.appendingPathComponent(download.isManaged ? UUID().uuidString + "-" + packageName : packageName)
			
			try FileManager.default.removeFileIfNeeded(at: destinationURL)
			try FileManager.default.moveItem(at: location, to: destinationURL)
			
            if download.isManaged {
                Task { @MainActor in
                    guard self.downloads.contains(where: { $0 === download }),
                          let stamp = download.managedGeneration,
                          ISignStore.shared.client?.generation == stamp else {
                        try? FileManager.default.removeItem(at: destinationURL); return
                    }
                    do { try self.handlePachageFile(url: destinationURL, dl: download) }
                    catch { ISignStore.shared.error = error.localizedDescription }
                }
            } else { try handlePachageFile(url: destinationURL, dl: download) }
		} catch {
			print("Error handling downloaded file: \(error.localizedDescription)")
		}
	}
	
	func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didWriteData bytesWritten: Int64, totalBytesWritten: Int64, totalBytesExpectedToWrite: Int64) {
		guard let download = getDownloadTask(by: downloadTask) else { return }
		
		DispatchQueue.main.async {
			download.progress = totalBytesExpectedToWrite > 0
			? Double(totalBytesWritten) / Double(totalBytesExpectedToWrite)
			: 0
			download.bytesDownloaded = totalBytesWritten
			download.totalBytes = totalBytesExpectedToWrite
			
			#if !targetEnvironment(macCatalyst)
			if #available(iOS 26.0, *) {
				BackgroundTaskManager.shared.updateProgress(for: download.id, progress: download.overallProgress)
			}
			#endif
		}
	}
	
	func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
		guard
			let _ = error,
			let downloadTask = task as? URLSessionDownloadTask,
			let download = getDownloadTask(by: downloadTask)
		else {
			return
		}
		
		DispatchQueue.main.async {
            if download.isManaged { self.retryManaged(download); return }
			if let index = self.getDownloadIndex(by: download.id) {
				self.downloads.remove(at: index)
			}
		}
	}
}

    extension DownloadManager {
        func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
            Task { @MainActor in
                guard let task = task as? URLSessionDownloadTask, let download = self.getDownloadTask(by: task), download.isManaged else { completionHandler(request); return }
                guard let url = request.url, download.managedPolicy?.allows(url) == true,
                      download.managedGeneration == ISignStore.shared.client?.generation else { completionHandler(nil); return }
                var clean = request
                clean.setValue(nil, forHTTPHeaderField: "Authorization")
                completionHandler(clean)
            }
        }
    }
