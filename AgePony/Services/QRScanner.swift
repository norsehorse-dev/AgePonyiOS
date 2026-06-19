//
//  QRScanner.swift
//  AgePony
//
//  AVFoundation-based QR-code scanner wrapped as a SwiftUI view. Used by
//  the Add Recipient → Scan path. The view fills its container with the
//  live camera preview and reports the first detected QR's string value
//  via `onDetect`. The host view is responsible for dismissing /
//  pausing the scanner after a detection — re-presenting the view starts
//  a fresh session.
//

import SwiftUI
import AVFoundation
import UIKit

struct QRScannerView: UIViewControllerRepresentable {

    let onDetect: (String) -> Void
    let onError: (QRScannerError) -> Void

    func makeUIViewController(context: Context) -> QRScannerViewController {
        let vc = QRScannerViewController()
        vc.delegate = context.coordinator
        return vc
    }

    func updateUIViewController(_ uiViewController: QRScannerViewController, context: Context) {
        // No-op; the scanner manages its own state.
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(onDetect: onDetect, onError: onError)
    }

    final class Coordinator: QRScannerViewControllerDelegate {
        let onDetect: (String) -> Void
        let onError: (QRScannerError) -> Void

        init(onDetect: @escaping (String) -> Void, onError: @escaping (QRScannerError) -> Void) {
            self.onDetect = onDetect
            self.onError = onError
        }

        func scannerDidDetect(_ value: String) {
            onDetect(value)
        }

        func scannerDidFail(_ error: QRScannerError) {
            onError(error)
        }
    }
}

enum QRScannerError: Error, Equatable {
    case cameraUnavailable
    case permissionDenied
    case setupFailed(String)
}

protocol QRScannerViewControllerDelegate: AnyObject {
    func scannerDidDetect(_ value: String)
    func scannerDidFail(_ error: QRScannerError)
}

final class QRScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {

    weak var delegate: QRScannerViewControllerDelegate?

    private let session = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var hasDelivered: Bool = false
    private let sessionQueue = DispatchQueue(label: "com.agepony.app.qr.session")

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        checkPermissionAndStart()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.layer.bounds
    }

    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        sessionQueue.async { [weak self] in
            self?.session.stopRunning()
        }
    }

    // MARK: - Setup

    private func checkPermissionAndStart() {
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            sessionQueue.async { [weak self] in self?.configureSession() }
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { [weak self] granted in
                guard let self = self else { return }
                if granted {
                    self.sessionQueue.async { self.configureSession() }
                } else {
                    DispatchQueue.main.async {
                        self.delegate?.scannerDidFail(.permissionDenied)
                    }
                }
            }
        case .denied, .restricted:
            delegate?.scannerDidFail(.permissionDenied)
        @unknown default:
            delegate?.scannerDidFail(.cameraUnavailable)
        }
    }

    private func configureSession() {
        guard let device = AVCaptureDevice.default(.builtInWideAngleCamera, for: .video, position: .back) else {
            DispatchQueue.main.async { self.delegate?.scannerDidFail(.cameraUnavailable) }
            return
        }

        do {
            let input = try AVCaptureDeviceInput(device: device)
            session.beginConfiguration()
            if session.canAddInput(input) {
                session.addInput(input)
            } else {
                session.commitConfiguration()
                DispatchQueue.main.async {
                    self.delegate?.scannerDidFail(.setupFailed("couldn't add camera input"))
                }
                return
            }

            let output = AVCaptureMetadataOutput()
            if session.canAddOutput(output) {
                session.addOutput(output)
                output.metadataObjectTypes = [.qr]
                output.setMetadataObjectsDelegate(self, queue: .main)
            } else {
                session.commitConfiguration()
                DispatchQueue.main.async {
                    self.delegate?.scannerDidFail(.setupFailed("couldn't add QR metadata output"))
                }
                return
            }
            session.commitConfiguration()

            // Preview layer set up on the main queue.
            DispatchQueue.main.async { [weak self] in
                guard let self = self else { return }
                let layer = AVCaptureVideoPreviewLayer(session: self.session)
                layer.videoGravity = .resizeAspectFill
                layer.frame = self.view.layer.bounds
                self.view.layer.insertSublayer(layer, at: 0)
                self.previewLayer = layer
            }

            session.startRunning()
        } catch {
            DispatchQueue.main.async {
                self.delegate?.scannerDidFail(.setupFailed(error.localizedDescription))
            }
        }
    }

    // MARK: - AVCaptureMetadataOutputObjectsDelegate

    func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !hasDelivered else { return }
        guard let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              obj.type == .qr,
              let value = obj.stringValue,
              !value.isEmpty else {
            return
        }
        hasDelivered = true
        // Stop the session so the camera stops draining battery as soon as
        // we've got a match; the host view will dismiss in response.
        sessionQueue.async { [weak self] in self?.session.stopRunning() }
        delegate?.scannerDidDetect(value)
    }
}
