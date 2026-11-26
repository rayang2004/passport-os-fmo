# Passport OS

<!-- impeccable:product-schema 1 -->

## Local minimal variant (2026-11-24)

The current requested variant removes Muse, personal portraits, names/signatures and card galleries. Home shows only time/date/weather plus an optional single uploaded background. Phone setup retains Wi-Fi, city/GPS and one background image; it does not retain portrait processing or multi-image management. Ambient mode uses a black background regardless of the configured image. The local variant also adds an experimental FMO foreground client with opt-in certificate application, a reused public trust root, signed relay discovery and half-duplex voice. Private keys stay local; original FMO credentials are not overwritten. Real issuance and network/audio interoperability remain unverified. See docs/CURRENT.md for build results and pending device validation. The Muse-specific commitments below describe the upstream baseline, not this variant.

## Platform

Embedded ESP32-C3 firmware with LVGL on a 240×320 screen. This is not a web, iOS or Android application. The browser artifact is a separate interaction preview.

## Users and purpose

The owner and people using the same AI Passport hardware use its physical buttons, display, microphone and speaker for portable voice input, assistants, radio and small utilities/games. The owner requested detailed setup documentation for other users.

## Operating context

The device has three physical buttons. Existing Wi-Fi and personal information are configured through a phone web page. Muse pairs with the owner's phone account; this owner's current network uses a computer HTTP proxy. Hold UP to record, release to send, OK pages a received reply, long OK returns. Muse and desktop voice-input are different apps.

## Capabilities and constraints

- ESP32-C3, 8 MB Flash, no PSRAM; preserve memory for Wi-Fi, encrypted connections and recording.
- App switching must release foreground resources. No black "returning" screens.
- Two consecutive Muse hardware reply displays were confirmed by the owner before this visual update. Long-term stability is not established by that short test.
- No supported Muse quota interface was found in the reviewed public SDK documentation. User explicitly requested removing quota from the UI.
- Default system theme is classic green; keep the alternative travel theme and existing button semantics.

## Muse visual commitment

On 2026-10-05 the user requested the displayed official Jollybot character as the Muse app's main visual, complete state motion/transitions, and explicit attention to memory stability. This is a scoped Muse app update. Official character assets have separate rights from SDK code; no public distribution is implied by the local hardware request.

## Evidence

Current firmware source, `DESIGN.md`, `docs/muse.md`, `docs/muse-visual.md`, and local diagnostics in the parent workspace document implementation and validation. Browser simulations, host LVGL snapshots and physical-device tests must be labelled separately.
