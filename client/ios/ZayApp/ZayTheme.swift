import SwiftUI
import UIKit

enum ZayTheme {
    /// Page background — follows system light / dark.
    static let canvas = Color(uiColor: .systemGroupedBackground)
    static let canvasDeep = Color(uiColor: .secondarySystemGroupedBackground)
    static let surface = Color(uiColor: .secondarySystemGroupedBackground)
    static let ink = Color(uiColor: .label)
    static let inkSecondary = Color(uiColor: .secondaryLabel)
    static let inkTertiary = Color(uiColor: .tertiaryLabel)
    static let hairline = Color(uiColor: .separator)

    static let accent = Color(uiColor: UIColor { tc in
        switch tc.userInterfaceStyle {
        case .dark:
            return UIColor(red: 0.28, green: 0.82, blue: 0.70, alpha: 1)
        default:
            return UIColor(red: 0.08, green: 0.55, blue: 0.48, alpha: 1)
        }
    })

    static let accentSoft = Color(uiColor: UIColor { tc in
        switch tc.userInterfaceStyle {
        case .dark:
            return UIColor(red: 0.35, green: 0.88, blue: 0.76, alpha: 1)
        default:
            return UIColor(red: 0.12, green: 0.68, blue: 0.58, alpha: 1)
        }
    })

    static let danger = Color(uiColor: UIColor { tc in
        switch tc.userInterfaceStyle {
        case .dark:
            return UIColor(red: 0.96, green: 0.42, blue: 0.38, alpha: 1)
        default:
            return UIColor(red: 0.86, green: 0.28, blue: 0.24, alpha: 1)
        }
    })

    static let connected = Color(uiColor: UIColor { tc in
        switch tc.userInterfaceStyle {
        case .dark:
            return UIColor(red: 0.35, green: 0.88, blue: 0.62, alpha: 1)
        default:
            return UIColor(red: 0.12, green: 0.62, blue: 0.42, alpha: 1)
        }
    })

    static let pending = Color(uiColor: UIColor { tc in
        switch tc.userInterfaceStyle {
        case .dark:
            return UIColor(red: 0.95, green: 0.78, blue: 0.35, alpha: 1)
        default:
            return UIColor(red: 0.82, green: 0.55, blue: 0.12, alpha: 1)
        }
    })

    static let brandFont = "Futura-Bold"
    static let titleFont = "AvenirNext-DemiBold"
    static let bodyFont = "AvenirNext-Medium"
    static let captionFont = "AvenirNext-Regular"
    static let monoFont = "Menlo-Regular"
}

struct ZayCanvas: View {
    var body: some View {
        ZayTheme.canvas.ignoresSafeArea()
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
