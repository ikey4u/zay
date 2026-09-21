#!/usr/bin/env swift

import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

guard CommandLine.arguments.count == 2 else {
    fputs("usage: generate-brand-assets.swift OUTPUT.png\n", stderr)
    exit(2)
}

let output = URL(fileURLWithPath: CommandLine.arguments[1])
try FileManager.default.createDirectory(
    at: output.deletingLastPathComponent(),
    withIntermediateDirectories: true
)

let side = 1024
let colorSpace = CGColorSpaceCreateDeviceRGB()
guard let context = CGContext(
    data: nil,
    width: side,
    height: side,
    bitsPerComponent: 8,
    bytesPerRow: side * 4,
    space: colorSpace,
    bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue
) else {
    fputs("failed to allocate icon canvas\n", stderr)
    exit(1)
}

let background = CGColor(red: 7 / 255, green: 23 / 255, blue: 19 / 255, alpha: 1)
let mint = CGColor(red: 45 / 255, green: 212 / 255, blue: 163 / 255, alpha: 1)

context.setFillColor(background)
context.fill(CGRect(x: 0, y: 0, width: side, height: side))

context.setStrokeColor(mint)
context.setLineWidth(118)
context.setLineCap(.round)
context.setLineJoin(.round)
context.move(to: CGPoint(x: 299, y: 704))
context.addLine(to: CGPoint(x: 725, y: 704))
context.addLine(to: CGPoint(x: 299, y: 320))
context.addLine(to: CGPoint(x: 725, y: 320))
context.strokePath()

context.setFillColor(background)
for point in [CGPoint(x: 299, y: 704), CGPoint(x: 725, y: 320)] {
    context.fillEllipse(in: CGRect(x: point.x - 32, y: point.y - 32, width: 64, height: 64))
}

guard let image = context.makeImage(),
      let destination = CGImageDestinationCreateWithURL(
          output as CFURL,
          UTType.png.identifier as CFString,
          1,
          nil
      )
else {
    fputs("failed to create icon encoder\n", stderr)
    exit(1)
}
CGImageDestinationAddImage(destination, image, nil)
guard CGImageDestinationFinalize(destination) else {
    fputs("failed to encode icon PNG\n", stderr)
    exit(1)
}
