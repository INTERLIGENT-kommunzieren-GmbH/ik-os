# Repository Guidelines

Custom Fedora-based OS image for Interligent Kommunizieren GmbH, built on Universal Blue (Bluefin-DX). This project follows the `bootc` and `ostree` patterns for immutable infrastructure.

## Project Structure & Module Organization

- **`./Containerfile`**: Multi-stage build that uses a bind mount to execute build scripts without polluting the final image.
- **`./build_files/`**: Contains the core logic and assets for image customization.
    - **`build.sh`**: The main execution script during build. It handles package installation, CA trust integration, VPN configuration, and system branding.
    - **`certs/`**: VPN and TLS certificates.
- **`./system_files/`**: Static configuration files (e.g., systemd units, presets, tmpfiles) that are layered into the image.
- **`./flatpaks/`**: Manifests for Flatpaks to be installed post-deployment using `ujust install-system-flatpaks`.
- **`./logos/`**: Branding assets for GDM and Plymouth watermarks.

## Build, Test, and Development Commands

Automation is handled via `just`.

- **Build image**: `just build` (uses `podman`)
- **Clean artifacts**: `just clean`
- **Lint Justfile**: `just check`
- **Format Justfile**: `just fix`
- **Image Linting**: Performed automatically during build via `bootc container lint`.

## Coding Style & Naming Conventions

- **Shell Scripts**: Must start with `set -ouex pipefail` for strict error handling and debugging.
- **Justfile**: Indented with tabs (as per `just` default) and must be formatted using `just --fmt`.
- **System Layout**: Files in `./system_files/` must mirror their destination paths (e.g., `./system_files/etc/...`).

## Testing Guidelines

The build process includes a verification step using `bootc container lint`. Ensure any changes to the system layout or package management don't break `bootc` compatibility.

## Commit Guidelines

Follow the informal but descriptive pattern seen in the history:
- `added <feature>`: For new capabilities or assets.
- `bugfix <component>`: For resolving issues.
- `switched to <base>`: For base image updates.
