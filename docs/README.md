# Documentation

Two audiences, kept apart on purpose. The first group is written for whoever runs bioseasy and is
also rendered inside the web UI under **Guide**. The second is written for whoever works on it and
stays in the repository.

## Running bioseasy

| | |
|---|---|
| [Concept](concept.md) | What the thing is, what Apple allows, and how the pieces fit. |
| [Your first backup](first-backup.md) | The short path from nothing to a finished backup. |
| [Installation](install.md) | Docker host, ports, storage, NAS mounts, HTTPS, updates. |
| [Configuration](configuration.md) | Every environment variable, with its default. |
| [Pairing a device](pairing.md) | The one-time trust step, and the four ways to do it. |
| [Setup wizard](setup.md) | The four steps per device, and what each one changes on the device. |
| [Restoring a backup](restore.md) | Getting data back, with Finder, iMazing or pymobiledevice3. |
| [Notifications](notifications.md) | Email, Telegram, browser notifications, Home Assistant over MQTT. |
| [Status API](api.md) | Read-only API and tokens, including the Shortcuts recipe. |
| [Troubleshooting](troubleshooting.md) | Symptom first, subsystem second. |

## Working on bioseasy

| | |
|---|---|
| [Building and releasing](building.md) | Checks, image build, helper app build, how a release is cut. |
| [Design tokens](design.md) | Colours, type scale and the layout primitive behind `static/app.css`. |
