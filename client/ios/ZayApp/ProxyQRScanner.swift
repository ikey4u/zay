import SwiftUI
import AVFoundation

struct ProxyQRScanner: View {
    let onScan: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var error: String?

    var body: some View {
        NavigationStack {
            CameraScanner(onScan: onScan, onError: { error = $0 })
                .overlay(alignment: .bottom) {
                    Text(error ?? "Point the camera at the server QR code.")
                        .padding()
                        .foregroundStyle(.white)
                        .background(.black.opacity(0.75), in: RoundedRectangle(cornerRadius: 12))
                        .padding()
                }
                .navigationTitle("Scan server QR code")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { dismiss() }
                    }
                }
        }
    }
}

private struct CameraScanner: UIViewControllerRepresentable {
    let onScan: (String) -> Void
    let onError: (String) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(onScan: onScan, onError: onError)
    }

    func makeUIViewController(context: Context) -> CameraViewController {
        CameraViewController(delegate: context.coordinator, onError: onError)
    }

    func updateUIViewController(_ camera: CameraViewController, context: Context) {}

    static func dismantleUIViewController(_ camera: CameraViewController, coordinator: Coordinator) {
        coordinator.finished = true
        camera.capture.stop()
    }

    final class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
        let onScan: (String) -> Void
        let onError: (String) -> Void
        var finished = false

        init(onScan: @escaping (String) -> Void, onError: @escaping (String) -> Void) {
            self.onScan = onScan
            self.onError = onError
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
            guard !finished else { return }
            for case let barcode as AVMetadataMachineReadableCodeObject in objects {
                guard let value = barcode.stringValue?.trimmingCharacters(in: .whitespacesAndNewlines) else { continue }
                guard let value = ProxyQRCode.supportedURL(value) else {
                    onError("This QR code is not a supported proxy or subscription URL.")
                    continue
                }
                finished = true
                onScan(value)
                return
            }
        }
    }
}

private final class CameraViewController: UIViewController {
    let capture = QRSession()
    private let delegate: AVCaptureMetadataOutputObjectsDelegate
    private let onError: (String) -> Void
    private var preview: AVCaptureVideoPreviewLayer?

    init(delegate: AVCaptureMetadataOutputObjectsDelegate, onError: @escaping (String) -> Void) {
        self.delegate = delegate
        self.onError = onError
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) is unavailable") }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        let preview = AVCaptureVideoPreviewLayer(session: capture.session)
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview)
        self.preview = preview
        capture.start(delegate: delegate, onError: onError)
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        preview?.frame = view.bounds
        guard let connection = preview?.connection, connection.isVideoOrientationSupported else { return }
        switch view.window?.windowScene?.interfaceOrientation {
        case .landscapeLeft: connection.videoOrientation = .landscapeLeft
        case .landscapeRight: connection.videoOrientation = .landscapeRight
        case .portraitUpsideDown: connection.videoOrientation = .portraitUpsideDown
        default: connection.videoOrientation = .portrait
        }
    }
}

// Configure and run capture away from the main thread. Queue ordering also
// prevents a delayed start from reopening the camera after sheet dismissal.
private final class QRSession {
    let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "dev.zay.qr-camera")
    private var stopped = false

    func start(delegate: AVCaptureMetadataOutputObjectsDelegate, onError: @escaping (String) -> Void) {
        queue.async { [self] in
            guard !stopped else { return }
            session.beginConfiguration()
            var configuring = true
            session.sessionPreset = .high
            do {
                guard let camera = AVCaptureDevice.default(for: .video) else {
                    throw CameraError.unavailable
                }
                let input = try AVCaptureDeviceInput(device: camera)
                let output = AVCaptureMetadataOutput()
                guard session.canAddInput(input) else { throw CameraError.unavailable }
                session.addInput(input)
                guard session.canAddOutput(output) else { throw CameraError.unavailable }
                session.addOutput(output)
                output.setMetadataObjectsDelegate(delegate, queue: .main)
                guard output.availableMetadataObjectTypes.contains(.qr) else { throw CameraError.unavailable }
                output.metadataObjectTypes = [.qr]
                session.commitConfiguration()
                configuring = false
                session.startRunning()
                if !session.isRunning { throw CameraError.unavailable }
            } catch {
                // Configuration must be committed before teardown can stop it.
                if configuring {
                    session.commitConfiguration()
                }
                DispatchQueue.main.async {
                    onError("Could not start the camera. Paste the import URL or close the scanner and try again.")
                }
            }
        }
    }

    func stop() {
        queue.async { [self] in
            stopped = true
            session.stopRunning()
        }
    }

    private enum CameraError: Error { case unavailable }
}
