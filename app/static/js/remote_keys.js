(() => {
  const keysyms = Object.freeze({
    alt: 0xffe9,
    backspace: 0xff08,
    control: 0xffe3,
    delete: 0xffff,
    escape: 0xff1b,
    f4: 0xffc1,
    r: 0x72,
    shift: 0xffe1,
    tab: 0xff09,
    windows: 0xffeb,
  });

  const sequences = Object.freeze([
    Object.freeze({ id: "ctrl-alt-delete", label: "Ctrl + Alt + Delete", keys: [keysyms.control, keysyms.alt, keysyms.delete] }),
    Object.freeze({ id: "ctrl-alt-backspace", label: "Ctrl + Alt + Backspace", keys: [keysyms.control, keysyms.alt, keysyms.backspace] }),
    Object.freeze({ id: "alt-tab", label: "Alt + Tab", keys: [keysyms.alt, keysyms.tab] }),
    Object.freeze({ id: "alt-f4", label: "Alt + F4", keys: [keysyms.alt, keysyms.f4] }),
    Object.freeze({ id: "ctrl-shift-escape", label: "Ctrl + Shift + Esc", keys: [keysyms.control, keysyms.shift, keysyms.escape] }),
    Object.freeze({ id: "windows", label: "Windows", keys: [keysyms.windows] }),
    Object.freeze({ id: "windows-r", label: "Windows + R", keys: [keysyms.windows, keysyms.r] }),
  ]);

  const sequenceById = new Map(sequences.map((sequence) => [sequence.id, sequence]));

  const sendKeySequence = ({ client, connected, displayReady, displayElement, markActivity, inputEnabled = true, id }) => {
    const sequence = sequenceById.get(id);
    if (!sequence || !inputEnabled || !client || !connected || !displayReady || !displayElement) return false;

    markActivity();
    const pressed = [];
    try {
      sequence.keys.forEach((keysym) => {
        pressed.push(keysym);
        client.sendKeyEvent(1, keysym);
      });
      return true;
    } finally {
      for (let index = pressed.length - 1; index >= 0; index -= 1) {
        try {
          client.sendKeyEvent(0, pressed[index]);
        } catch (_error) {
          // Continue releasing the remaining keys and always restore focus.
        }
      }
      displayElement.focus({ preventScroll: true });
      markActivity();
    }
  };

  window.KayaRemoteKeys = Object.freeze({ sequences, sendKeySequence });
})();
