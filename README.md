# DreamMosaic — Private Photo Mosaic PWA

> **A private, high-fidelity photographic mosaic application strictly for two people: you and your partner.**

Recreates your defining photograph using hundreds or thousands of smaller personal photographs as individual mosaic tiles. Built with perceptual **CIELAB Delta-E** color matching, spatial neighbor penalty algorithms, and zero-knowledge cryptographic security keys.

## Key Features

1. **Genuine Photographic Mosaic**
   - High-precision perceptual color matching in **CIE L*a*b* (D65)** color space.
   - Spatial Neighbor Penalty to avoid placing the same memory tile next to itself.
   - Configurable photo reuse: Balanced, Strict, or Unlimited.
   - Adjustable target-image blending (0%–40%).
   - Classic and Dreamy artistic modes.

2. **Mobile & PWA Ready**
   - Installable on iPhone Safari via Share → Add to Home Screen.
   - Responsive on iPhone, Android, and desktop.
   - Touch-friendly pan and zoom, before/after comparison, tile inspector, and PNG export.

3. **Private Two-User Cryptographic Security**
   - Exactly two roles: Owner (Administrator) and Partner (Member).
   - No public registration, passwords, email login, or social accounts.
   - High-entropy access keys with Scrypt hashing and constant-time comparison.
   - Login rate limiting, HttpOnly session cookies, and protected photo endpoints.

4. **Photo Ingestion**
   - Main image, multi-file, and folder upload.
   - ZIP extraction in the browser.
   - SHA-256 duplicate detection.

## Architecture

- Backend: Node.js HTTP service using built-in modules.
- Database: SQLite.
- Frontend: Progressive Web App.
- Image processing: Python, Pillow, NumPy, and CIELAB color conversion.

## Local Setup

Requirements: Node.js 18+, Python 3, Pillow, and NumPy.

```bash
pip install Pillow numpy
npm start
```

Open http://localhost:3001.

Run backend tests with:

```bash
npm test
```

## First-Time Setup

1. Open the app.
2. Generate the Owner and Partner keys.
3. Save the Owner key securely.
4. Share the Partner key privately.
5. Log in using the appropriate key.

**Deployment note:** SQLite and uploaded photos require persistent storage. Do not deploy this configuration to ephemeral storage if you need durable photo storage.
