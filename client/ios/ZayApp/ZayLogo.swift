import SwiftUI

struct ZayLogoMark: View {
    var size: CGFloat = 80

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.23, style: .continuous)
                .fill(ZayTheme.logoBackground)

            route
                .stroke(
                    ZayTheme.logoMint,
                    style: StrokeStyle(
                        lineWidth: size * 0.115,
                        lineCap: .round,
                        lineJoin: .round
                    )
                )

            endpoint(x: 0.292, y: 0.313)
            endpoint(x: 0.708, y: 0.688)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }

    private var route: Path {
        var path = Path()
        path.move(to: CGPoint(x: size * 0.292, y: size * 0.313))
        path.addLine(to: CGPoint(x: size * 0.708, y: size * 0.313))
        path.addLine(to: CGPoint(x: size * 0.292, y: size * 0.688))
        path.addLine(to: CGPoint(x: size * 0.708, y: size * 0.688))
        return path
    }

    private func endpoint(x: CGFloat, y: CGFloat) -> some View {
        Circle()
            .fill(ZayTheme.logoBackground)
            .frame(width: size * 0.063, height: size * 0.063)
            .position(x: size * x, y: size * y)
    }
}

struct ZayWordmark: View {
    var body: some View {
        VStack(spacing: 14) {
            ZayLogoMark(size: 88)

            Text("ZAY")
                .font(.custom(ZayTheme.brandFont, size: 30))
                .tracking(8)
                .foregroundStyle(ZayTheme.ink)
                .padding(.leading, 8)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Zay")
    }
}
