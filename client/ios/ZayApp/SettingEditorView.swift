import SwiftUI
import UIKit
import AVFoundation
import PhotosUI

struct SettingEditorView: View {
    let field: SettingField

    @EnvironmentObject private var configStore: ConfigStore
    @FocusState private var focused: Bool
    @State private var draft: String = ""
    @State private var showingScanner = false
    @State private var scannerError: String?
    @State private var qrPhoto: PhotosPickerItem?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            Section {
                Group {
                    if field.isSecure {
                        SecureField(field.placeholder, text: $draft)
                            .focused($focused)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(field.keyboard)
                            .textContentType(.password)
                            .font(.custom(ZayTheme.monoFont, size: 16))
                    } else {
                        TextField(field.placeholder, text: $draft, axis: .vertical)
                            .focused($focused)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .keyboardType(field.keyboard)
                            .textContentType(.none)
                            .font(.custom(ZayTheme.monoFont, size: 16))
                            .lineLimit(3...6)
                    }
                }
                .foregroundStyle(ZayTheme.ink)
                .listRowInsets(EdgeInsets(top: 14, leading: 16, bottom: 14, trailing: 16))
            } footer: {
                Text(field.subtitle)
                    .font(.custom(ZayTheme.captionFont, size: 13))
                    .foregroundStyle(ZayTheme.inkSecondary)
            }

            if field == .proxyURL {
                Section {
                    Button {
                        focused = false
                        Task { await openScanner() }
                    } label: {
                        Label("Scan server QR code", systemImage: "qrcode.viewfinder")
                    }
                    PhotosPicker(selection: $qrPhoto, matching: .images) {
                        Label("Import QR code from photo", systemImage: "photo")
                    }
                }
            }

            if !draft.isEmpty {
                Section {
                    Button(role: .destructive) {
                        draft = ""
                    } label: {
                        Text("清除内容")
                            .frame(maxWidth: .infinity)
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .background(ZayTheme.canvas.ignoresSafeArea())
        .scrollDismissesKeyboard(.interactively)
        .navigationTitle(field.title)
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(ZayTheme.canvas, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button("完成") {
                    commit()
                    focused = false
                    dismiss()
                }
                .font(.custom(ZayTheme.bodyFont, size: 16))
                .fontWeight(.semibold)
            }
            ToolbarItemGroup(placement: .keyboard) {
                Spacer()
                Button("完成") {
                    focused = false
                    commit()
                }
            }
        }
        .onAppear {
            draft = configStore.config[keyPath: field.keyPath]
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) {
                focused = true
            }
        }
        .onDisappear {
            commit()
        }
        .sheet(isPresented: $showingScanner) {
            ProxyQRScanner { url in
                draft = url
                commit()
                showingScanner = false
            }
        }
        .onChange(of: qrPhoto) { item in
            guard let item else { return }
            focused = false
            Task {
                defer { qrPhoto = nil }
                do {
                    guard let data = try await item.loadTransferable(type: Data.self) else {
                        scannerError = "Could not read the selected photo. Choose another photo or paste the import URL."
                        return
                    }
                    let url = try await Task.detached(priority: .userInitiated) {
                        try ProxyQRCode.readPhoto(data)
                    }.value
                    draft = url
                    commit()
                } catch {
                    scannerError = error.localizedDescription
                }
            }
        }
        .alert("Cannot import QR code", isPresented: Binding(
            get: { scannerError != nil },
            set: { if !$0 { scannerError = nil } }
        )) {
            Button("OK", role: .cancel) { scannerError = nil }
        } message: {
            Text(scannerError ?? "")
        }
    }

    @MainActor
    private func openScanner() async {
        guard await AVCaptureDevice.requestAccess(for: .video) else {
            scannerError = "Allow camera access for Zay in Settings to scan a server QR code."
            return
        }
        showingScanner = true
    }

    private func commit() {
        let current = configStore.config[keyPath: field.keyPath]
        guard current != draft else { return }
        configStore.update { $0[keyPath: field.keyPath] = draft }
    }
}
