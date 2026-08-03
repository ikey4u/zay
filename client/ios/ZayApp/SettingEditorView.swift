import SwiftUI
import UIKit

struct SettingEditorView: View {
    let field: SettingField

    @EnvironmentObject private var configStore: ConfigStore
    @FocusState private var focused: Bool
    @State private var draft: String = ""
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
    }

    private func commit() {
        let current = configStore.config[keyPath: field.keyPath]
        guard current != draft else { return }
        configStore.update { $0[keyPath: field.keyPath] = draft }
    }
}
