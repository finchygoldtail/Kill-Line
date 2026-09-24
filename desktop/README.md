# Kill Line desktop app

A native window around the Kill Line dashboard, built with [Tauri 2](https://tauri.app). Linux only for now.

## What happens when you open it

1. The app shows a start screen and asks the system for **administrator permission** (polkit / `pkexec`). Kill Line needs root to load its observe-only eBPF sensor into the kernel.
2. It starts the bundled engine (`killline ui --port 0 --announce-json --exit-with-stdin`) as root and reads the dashboard address and access token from it.
3. The window shows the dashboard, served by the engine on `127.0.0.1` only.
4. You get **native desktop notifications** when an agent crosses a boundary, or when Kill Line loses visibility (GREY).
5. Closing the app stops the engine. Monitors you started keep running; they show up again the next time you open the app.

## Security

- **No Tauri APIs for the dashboard.** The dashboard page comes from the local engine, and the capability file grants Tauri IPC only to the bundled start screen.
- **Navigation guard.** The window may load only the start screen and the engine's exact origin (`http://127.0.0.1:<port>`). Any other link or redirect is refused.
- **Checked announcement.** The engine's announcement is validated: the address must be loopback, on the announced port, with a 128-bit token. Otherwise the app refuses to connect.
- **Stopping a root process.** The app cannot signal the root engine, so it holds the engine's stdin open and closes it on exit. The engine was started with `--exit-with-stdin` and exits when that happens.
- **Polkit policy.** The `.deb` installs `org.killline.dashboard.policy`, so the password prompt explains why permission is needed.

## Build

```sh
sudo apt install clang libbpf-dev libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev libayatana-appindicator3-dev
cargo install tauri-cli --version "^2" --locked
desktop/build.sh
```

The output is `desktop/src-tauri/target/release/bundle/deb/Kill Line_0.1.0_amd64.deb` and an AppImage. Install the `.deb` with `sudo apt install "./Kill Line_0.1.0_amd64.deb"` and launch **Kill Line** from the applications menu.

For development, run `KILLLINE_BIN=/path/to/killline cargo run` inside `src-tauri/`.

## Not yet

- Windows and macOS. They need their own sensors; see `docs/ROADMAP.md`.
- Signed packages and auto-update. Updates will be opt-in and signature-checked.
- A tray icon with a live status colour.
