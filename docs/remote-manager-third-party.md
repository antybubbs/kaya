# Remote Manager Third-Party Notice

HomeLab Remote Manager's replacement SSH service is based on the same core architecture used by Termix:

- WebSocket transport between browser and backend
- Node.js SSH backend using `ssh2`
- xterm-compatible PTY sessions using `xterm-256color`
- JSON messages for `connectToHost`, `input`, `resize`, and `disconnect`

Termix is licensed under the Apache License, Version 2.0.

Original project: https://github.com/Termix-SSH/Termix

Copyright 2025 Luke Gustafson
