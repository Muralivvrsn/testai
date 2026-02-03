# Build Assets

This directory contains build assets for electron-builder.

## App Icon

The `icon.svg` file is the source icon. To build the app, you need to generate
PNG versions at various sizes.

### Generate icon.png (512x512)

Using ImageMagick:
```bash
convert icon.svg -resize 512x512 icon.png
```

Or using macOS sips:
```bash
# First convert SVG to PNG using a browser or design tool
# Then resize if needed:
sips -z 512 512 icon.png
```

### For macOS builds (.icns)

macOS requires an `.icns` file with multiple resolutions. You can use `iconutil`:

```bash
# Create iconset directory
mkdir icon.iconset

# Generate all sizes from icon.png
sips -z 16 16     icon.png --out icon.iconset/icon_16x16.png
sips -z 32 32     icon.png --out icon.iconset/icon_16x16@2x.png
sips -z 32 32     icon.png --out icon.iconset/icon_32x32.png
sips -z 64 64     icon.png --out icon.iconset/icon_32x32@2x.png
sips -z 128 128   icon.png --out icon.iconset/icon_128x128.png
sips -z 256 256   icon.png --out icon.iconset/icon_128x128@2x.png
sips -z 256 256   icon.png --out icon.iconset/icon_256x256.png
sips -z 512 512   icon.png --out icon.iconset/icon_256x256@2x.png
sips -z 512 512   icon.png --out icon.iconset/icon_512x512.png
sips -z 1024 1024 icon.png --out icon.iconset/icon_512x512@2x.png

# Convert to .icns
iconutil -c icns icon.iconset

# Clean up
rm -rf icon.iconset
```

### For Windows builds (.ico)

Windows requires an `.ico` file. You can use ImageMagick:

```bash
convert icon.png -define icon:auto-resize=256,128,64,48,32,16 icon.ico
```

Or use an online converter like https://icoconvert.com/

## electron-builder Notes

electron-builder will automatically look for:
- `build/icon.png` - Used as source, converted automatically
- `build/icon.icns` - macOS (optional, auto-generated from png)
- `build/icon.ico` - Windows (optional, auto-generated from png)

If you only provide `icon.png`, electron-builder will attempt to generate
the platform-specific formats automatically.

## Quick Start

For quick testing, just create a 512x512 PNG named `icon.png` in this directory.
You can use any image editor or online tool to convert the SVG.
