import SwiftUI

enum ZayTheme {
    // Cool stone paper — WeChat-like, not cream.
    static let canvas = Color(red: 0.93, green: 0.94, blue: 0.95)
    static let canvasDeep = Color(red: 0.88, green: 0.90, blue: 0.92)
    static let surface = Color.white
    static let ink = Color(red: 0.10, green: 0.12, blue: 0.14)
    static let inkSecondary = Color(red: 0.45, green: 0.48, blue: 0.52)
    static let inkTertiary = Color(red: 0.62, green: 0.65, blue: 0.68)
    static let hairline = Color.black.opacity(0.08)
    static let accent = Color(red: 0.08, green: 0.55, blue: 0.48)
    static let accentSoft = Color(red: 0.12, green: 0.68, blue: 0.58)
    static let danger = Color(red: 0.86, green: 0.28, blue: 0.24)
    static let connected = Color(red: 0.12, green: 0.62, blue: 0.42)
    static let pending = Color(red: 0.82, green: 0.55, blue: 0.12)

    static let brandFont = "Futura-Bold"
    static let titleFont = "AvenirNext-DemiBold"
    static let bodyFont = "AvenirNext-Medium"
    static let captionFont = "AvenirNext-Regular"
    static let monoFont = "Menlo-Regular"
}

struct ZayCanvas: View {
    var body: some View {
        ZStack {
            LinearGradient(
                colors: [ZayTheme.canvas, ZayTheme.canvasDeep],
                startPoint: .top,
                endPoint: .bottom
            )
            // Soft top wash for atmosphere without looking like a flat fill.
            RadialGradient(
                colors: [
                    ZayTheme.accentSoft.opacity(0.10),
                    .clear,
                ],
                center: UnitPoint(x: 0.15, y: 0.0),
                startRadius: 10,
                endRadius: 320
            )
        }
        .ignoresSafeArea()
    }
}

struct SettingsGroup<Content: View>: View {
    @ViewBuilder var content: Content

    var body: some View {
        VStack(spacing: 0) {
            content
        }
        .background(ZayTheme.surface)
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
    }
}

struct SettingsRow: View {
    let title: String
    var value: String = ""
    var valueMuted: Bool = false
    var showChevron: Bool = true

    var body: some View {
        HStack(spacing: 12) {
            Text(title)
                .font(.custom(ZayTheme.bodyFont, size: 16))
                .foregroundStyle(ZayTheme.ink)
                .lineLimit(1)

            Spacer(minLength: 8)

            if !value.isEmpty {
                Text(value)
                    .font(.custom(ZayTheme.captionFont, size: 15))
                    .foregroundStyle(valueMuted ? ZayTheme.inkTertiary : ZayTheme.inkSecondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            if showChevron {
                Image(systemName: "chevron.right")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(ZayTheme.inkTertiary.opacity(0.7))
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 14)
        .contentShape(Rectangle())
    }
}

struct SettingsDivider: View {
    var body: some View {
        Rectangle()
            .fill(ZayTheme.hairline)
            .frame(height: 0.5)
            .padding(.leading, 16)
    }
}
