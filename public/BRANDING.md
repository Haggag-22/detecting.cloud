# Static branding assets (`/public`)

| File | Purpose |
|------|--------|
| **`favicon.png`** | Default favicon (`<link rel="icon">`). Tab icon; keep square, ≥48×48 recommended. |
| **`logo.png`** | Apple touch icon / home-screen icon (`<link rel="apple-touch-icon">`). Same brand mark, typically 180×180+ (current file is high-res; iOS scales down). |
| **`preview.png`** | **Link-preview image** for Open Graph + Twitter (`https://detecting.cloud/preview.png`). Replace with a **1200×630** (or similar) marketing image for best social cards. Current file is a copy of `og-image.png` as a starting point. |

Regenerate favicons after changing the logo:

```bash
# From repo root (macOS)
sips -s format png src/assets/logo.png --out public/favicon.png
sips -z 32 32 public/favicon.png --out public/favicon-32.png
sips -z 16 16 public/favicon.png --out public/favicon-16.png
npx --yes to-ico public/favicon-32.png > public/favicon.ico
cp src/assets/logo.png public/logo.png
```

No Lovable favicons or meta tags are used in `index.html`.
