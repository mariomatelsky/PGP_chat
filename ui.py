
import curses
import queue
import socket
import threading
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional, Tuple

LEFT_W      = 24    # contacts panel total width (including both border cols)
MIN_W       = 80
MIN_H       = 20

PING_INTERVAL = 20   # seconds between TCP probe cycles
PING_TIMEOUT  = 1.2

STANDBY  = "STANDBY"
CHATTING = "CHATTING"

# colour pair indices
CP_BODY   = 1   # green on black   — body text
CP_BORDER = 2   # green on black + BOLD — borders / chrome
CP_HDR    = 3   # black on green   — header bar (reverse video)
CP_AMBER  = 4   # yellow on black  — panel titles, system info
CP_ERR    = 5   # red on black     — errors / warnings
CP_ME     = 6   # white on black   — own messages
CP_SEL    = 7   # black on yellow  — selected / active contact
CP_DIM    = 8   # green on black + DIM — offline contacts, idle text

def _ping(host: str, port: int) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=PING_TIMEOUT)
        s.close()
        return True
    except Exception:
        return False


def _clock() -> str:
    return datetime.now().strftime("%H:%M:%S")


def _mts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%H:%M")


def _safe(stdscr, row: int, col: int, text: str, attr: int = 0) -> None:
    try:
        stdscr.addstr(row, col, text, attr)
    except curses.error:
        pass


def _safech(stdscr, row: int, col: int, ch: str, attr: int = 0) -> None:
    try:
        stdscr.addch(row, col, ch, attr)
    except curses.error:
        pass


class RetroUI:
    """Split-panel terminal UI. STANDBY until CONNECTED event, then CHATTING."""

    def __init__(
        self,
        my_nick:       str,
        contacts:      List[Dict],
        port:          int,
        incoming_q:    queue.Queue,
        outgoing_q:    queue.Queue,
        on_message:    Callable[[str], None],
        on_quit:       Callable[[], None],
        active_fp:     Optional[str] = None,
        standby_msg:   str           = "",
        listener_mode: bool          = False,
    ):
        self.my_nick     = my_nick
        self.contacts    = contacts
        self.port        = port
        self.in_q        = incoming_q
        self.out_q       = outgoing_q
        self.on_message  = on_message
        self.on_quit     = on_quit
        self.active_fp     = active_fp or ""
        self.standby_msg   = standby_msg or f"LISTENING ON PORT {port}"
        self.listener_mode = listener_mode

        # Chat state
        self.state      = STANDBY
        self.peer_nick  = ""
        self.peer_fp    = active_fp or ""
        self.messages: List[Tuple] = []  # (ts, nick, text, color_key)
        self.scroll     = 0              # lines scrolled up from bottom
        self.input_buf  = ""

        # Online status {fingerprint: bool}
        self.online: Dict[str, bool] = {
            c["fingerprint"]: False for c in contacts
        }

        self._running         = True
        self._pinger_stop     = threading.Event()


    def run(self) -> None:
        curses.wrapper(self._main)


    def _start_pinger(self) -> None:
        def loop():
            # Immediate first pass
            self._ping_all()
            while not self._pinger_stop.wait(timeout=PING_INTERVAL):
                self._ping_all()

        threading.Thread(target=loop, daemon=True).start()

    def _ping_all(self) -> None:
        for c in self.contacts:
            if c.get("host"):
                self.online[c["fingerprint"]] = _ping(
                    c["host"], c.get("port", self.port)
                )


    def _drain(self) -> None:
        while True:
            try:
                self._handle_event(self.in_q.get_nowait())
            except queue.Empty:
                break

    def _handle_event(self, ev: tuple) -> None:
        kind = ev[0]
        if kind == "LISTENING":
            self.standby_msg = f"LISTENING ON PORT {ev[2]}"

        elif kind == "CONNECTED":
            self.state     = CHATTING
            self.peer_nick = ev[1]
            if not self.peer_fp:
                for c in self.contacts:
                    if c["name"] == ev[1]:
                        self.peer_fp = c["fingerprint"]
                        break
            self._sys(f"SECURE SESSION ESTABLISHED WITH {self.peer_nick.upper()}")
            self._sys(f"FINGERPRINT: {self.peer_fp}")
            self._sys("TYPE /HELP FOR COMMANDS")
            print("\a", end="", flush=True)

        elif kind == "MSG":
            _, nick, text, ts = ev
            self.messages.append((ts, nick, text, "peer"))
            if self.scroll > 0:
                self.scroll += 1   # keep the view stable
            print("\a", end="", flush=True)

        elif kind == "DISCONNECT":
            self._sys(f">> {ev[1].upper()} DISCONNECTED  <<")
            self.state    = STANDBY
            self._running = False

        elif kind == "WARNING":
            self._sys(f"WARN: {ev[2]}", "err")

        elif kind == "ERROR":
            self._sys(f"ERR:  {ev[2]}", "err")
            if self.state == STANDBY:
                if self.listener_mode:
                    self._sys("Press /quit to exit or wait for a new connection.", "sys")
                else:
                    self._sys("Press /quit to exit.", "sys")

    def _sys(self, text: str, color: str = "sys") -> None:
        self.messages.append((time.time(), "SYSTEM", text, color))


    def _handle_key(self, ch, msg_rows: int) -> None:
        if ch in (curses.KEY_ENTER, ord("\n"), ord("\r"), "\n", "\r"):
            self._submit()
        elif ch in (curses.KEY_BACKSPACE, ord("\x7f"), ord("\b"), "\x7f", "\b"):
            self.input_buf = self.input_buf[:-1]
        elif ch == curses.KEY_UP:
            top = max(0, len(self.messages) - msg_rows)
            self.scroll = min(self.scroll + 1, top)
        elif ch == curses.KEY_DOWN:
            self.scroll = max(0, self.scroll - 1)
        elif ch == curses.KEY_PPAGE:
            top = max(0, len(self.messages) - msg_rows)
            self.scroll = min(self.scroll + msg_rows // 2, top)
        elif ch == curses.KEY_NPAGE:
            self.scroll = max(0, self.scroll - msg_rows // 2)
        elif isinstance(ch, str) and ch.isprintable():
            self.input_buf += ch
        elif isinstance(ch, int) and 32 <= ch < 127:
            self.input_buf += chr(ch)

    def _submit(self) -> None:
        text  = self.input_buf.strip()
        self.input_buf = ""
        if not text:
            return
        lower = text.lower()
        if lower in ("/quit", "/q", "/exit"):
            self._sys(">> DISCONNECTING <<")
            self._running = False
            self.on_quit()
        elif lower == "/help":
            for ln in [
                "  /help   — this message",
                "  /fp     — show peer fingerprint",
                "  /clear  — clear display (log kept on disk)",
                "  /quit   — disconnect and exit",
                "  UP/DN   — scroll  |  PGUP/PGDN — page",
            ]:
                self._sys(ln)
        elif lower == "/fp":
            self._sys(f"PEER: {self.peer_nick}  FP: {self.peer_fp}")
        elif lower == "/clear":
            self.messages.clear()
            self.scroll = 0
        elif text.startswith("/"):
            self._sys(f"UNKNOWN COMMAND: {text}  (try /help)", "err")
        elif self.state == CHATTING:
            self.on_message(text)
            self.messages.append((time.time(), self.my_nick, text, "me"))
            self.scroll = 0
        else:
            self._sys("NOT CONNECTED — WAITING FOR PEER")


    def _setup_colors(self) -> None:
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(CP_BODY,   curses.COLOR_GREEN,  -1)
        curses.init_pair(CP_BORDER, curses.COLOR_GREEN,  -1)
        curses.init_pair(CP_HDR,    curses.COLOR_BLACK,  curses.COLOR_GREEN)
        curses.init_pair(CP_AMBER,  curses.COLOR_YELLOW, -1)
        curses.init_pair(CP_ERR,    curses.COLOR_RED,    -1)
        curses.init_pair(CP_ME,     curses.COLOR_WHITE,  -1)
        curses.init_pair(CP_SEL,    curses.COLOR_BLACK,  curses.COLOR_YELLOW)
        curses.init_pair(CP_DIM,    curses.COLOR_GREEN,  -1)

    def _hline(self, stdscr, row: int, lc: str, mc: str, rc: str, lw: int, w: int) -> None:
        BDR = curses.color_pair(CP_BORDER) | curses.A_BOLD
        _safech(stdscr, row, 0,     lc, BDR)
        for c in range(1, lw - 1):
            _safech(stdscr, row, c, '═', BDR)
        _safech(stdscr, row, lw - 1, mc, BDR)
        for c in range(lw, w - 1):
            _safech(stdscr, row, c, '═', BDR)
        try:
            stdscr.addch(row, w - 1, rc, BDR)
        except curses.error:
            pass


    def _draw_frame(self, stdscr, h: int, w: int, lw: int) -> None:
        BDR = curses.color_pair(CP_BORDER) | curses.A_BOLD
        # Horizontal rules
        self._hline(stdscr, 1,   '╔', '╦', '╗', lw, w)
        self._hline(stdscr, 3,   '╠', '╬', '╣', lw, w)
        self._hline(stdscr, h-3, '╠', '╬', '╣', lw, w)
        self._hline(stdscr, h-1, '╚', '╩', '╝', lw, w)
        # Vertical bars
        for row in range(2, h - 1):
            if row in (3, h - 3):
                continue
            _safech(stdscr, row, 0,      '║', BDR)
            _safech(stdscr, row, lw - 1, '║', BDR)
            if row < h - 1:
                _safech(stdscr, row, w - 1, '║', BDR)


    def _draw_header(self, stdscr, h: int, w: int) -> None:
        HDR  = curses.color_pair(CP_HDR) | curses.A_BOLD
        ts   = _clock()
        left = f" ░▒▓█ PGPCHAT █▓▒░  ·  RSA-4096 // AES-256-GCM  ·  {self.my_nick}"
        right = f"{ts} "
        gap  = max(1, w - len(left) - len(right))
        line = (left + " " * gap + right)[:w]
        _safe(stdscr, 0, 0, line.ljust(w)[:w], HDR)


    def _draw_titles(self, stdscr, h: int, w: int, lw: int) -> None:
        AMB = curses.color_pair(CP_AMBER) | curses.A_BOLD
        ri  = w - lw - 2   # usable cols in right panel

        # Left title
        lt = " C O N T A C T S"
        _safe(stdscr, 2, 1, lt[:lw - 2].ljust(lw - 2), AMB)

        # Right title
        if self.state == CHATTING:
            rt_left = f" CHANNEL : {self.peer_nick.upper()}"
        else:
            rt_left = f" {self.standby_msg}"
        enc_tag  = "[ ENCRYPTED ] "
        pad      = max(0, ri - len(rt_left) - len(enc_tag))
        rt_line  = (rt_left + " " * pad + enc_tag)[:ri]
        _safe(stdscr, 2, lw, rt_line.ljust(ri)[:ri], AMB)


    def _draw_contacts(self, stdscr, h: int, w: int, lw: int) -> None:
        content_rows = h - 7          # rows 4 … h-4
        inner        = lw - 2         # printable cols between the borders
        BDY = curses.color_pair(CP_BODY)
        AMB = curses.color_pair(CP_AMBER) | curses.A_BOLD

        for i, c in enumerate(self.contacts):
            row = 4 + i
            if row > h - 4:
                break

            fp       = c["fingerprint"]
            name     = c["name"][:13]
            is_chat  = (fp == self.peer_fp) and self.state == CHATTING
            is_on    = self.online.get(fp, False)

            arrow    = "►" if is_chat else " "
            dot      = "●" if is_on  else "○"
            line     = f" {arrow} {name:<13} {dot} "[:inner].ljust(inner)

            if is_chat:
                attr = curses.color_pair(CP_SEL) | curses.A_BOLD
            elif is_on:
                attr = curses.color_pair(CP_BODY) | curses.A_BOLD
            else:
                attr = curses.color_pair(CP_DIM) | curses.A_DIM

            _safe(stdscr, row, 1, line, attr)

        n_on    = sum(1 for on in self.online.values() if on)
        n_total = len(self.contacts)
        dot_a   = curses.color_pair(CP_BODY) | curses.A_BOLD
        txt_a   = curses.color_pair(CP_AMBER)
        st_text = f"  {n_on} / {n_total}  ONLINE  "[:inner].ljust(inner)
        _safe(stdscr, h - 2, 1, "  ", txt_a)
        _safe(stdscr, h - 2, 1, " ●", dot_a)
        _safe(stdscr, h - 2, 3, st_text[2:].ljust(inner - 2), txt_a)


    def _draw_standby(self, stdscr, h: int, w: int, lw: int) -> None:
        ri   = w - lw - 2
        col  = lw          # first usable column in right panel
        AMB  = curses.color_pair(CP_AMBER) | curses.A_BOLD
        DIM  = curses.color_pair(CP_DIM)   | curses.A_DIM
        ERR  = curses.color_pair(CP_ERR)   | curses.A_BOLD

        blink = int(time.time() * 2) % 2 == 0

        logo = [
            "",
            "   ╔═══════════════════════╗",
            "   ║  ░░ P G P C H A T ░░  ║",
            "   ║   SECURE COMMS v1.0   ║",
            "   ║  RSA-4096 // AES-256  ║",
            "   ╚═══════════════════════╝",
            "",
            f"   {self.standby_msg}",
            "",
            f"   {'▌ AWAITING SECURE CONNECTION ▌' if blink else '░ AWAITING SECURE CONNECTION ░'}",
            "",
            "   pgpchat call <name>  to initiate",
            "   /quit               to stop",
        ]

        for i, line in enumerate(logo):
            row = 4 + i
            if row > h - 4:
                break
            is_logo   = 1 <= i <= 5
            is_status = i in (7, 9)
            attr      = AMB if (is_logo or is_status) else DIM
            _safe(stdscr, row, col, line[:ri + 1].ljust(ri + 1)[:ri + 1], attr)

        # Show recent system/error messages so handshake failures are visible
        recent_msgs = [m for m in self.messages if m[3] in ("err", "sys")][-4:]
        for j, (ts, nick, text, ck) in enumerate(recent_msgs):
            row = 4 + len(logo) + j
            if row > h - 4:
                break
            attr = ERR if ck == "err" else AMB
            _safe(stdscr, row, col, f"   {text}"[: ri + 1].ljust(ri + 1)[: ri + 1], attr)


    def _draw_messages(self, stdscr, h: int, w: int, lw: int) -> None:
        ri           = w - lw - 2
        content_rows = h - 7
        col          = lw
        bubble_max   = max(10, int(ri * 0.72))  # bubbles use at most 72% of panel

        color_map = {
            "me":   curses.color_pair(CP_ME)    | curses.A_BOLD,
            "peer": curses.color_pair(CP_BODY)  | curses.A_BOLD,
            "sys":  curses.color_pair(CP_AMBER),
            "err":  curses.color_pair(CP_ERR),
        }

        total    = len(self.messages)
        view_end = max(0, total - self.scroll)
        view_st  = max(0, view_end - content_rows)
        visible  = self.messages[view_st:view_end]

        for i, (ts, nick, text, ck) in enumerate(visible):
            row  = 4 + i
            attr = color_map.get(ck, curses.color_pair(CP_BODY))
            ts_s = _mts(ts)

            if ck == "me":
                # Right side: "text  Nick · HH:MM ▶"  right-justified
                suffix = f"  {nick} · {ts_s} ▶"
                avail  = bubble_max - len(suffix)
                body   = text[:max(0, avail)]
                content = body + suffix
                line   = content.rjust(ri)[:ri]
            elif ck == "peer":
                # Left side: "◀ HH:MM · Nick  text"  left-justified
                prefix = f"◀ {ts_s} · {nick}  "
                avail  = bubble_max - len(prefix)
                body   = text[:max(0, avail)]
                content = prefix + body
                line   = content.ljust(ri)[:ri]
            else:
                # System / error: centred
                content = f"── {text} ──"
                line    = content[:ri].center(ri)[:ri]

            _safe(stdscr, row, col, line, attr)

        if self.scroll > 0:
            unread_txt = f" ↓ {self.scroll} more "
            _safe(stdscr, h - 4, col + ri - len(unread_txt),
                  unread_txt, curses.color_pair(CP_SEL) | curses.A_BOLD)


    def _draw_input(self, stdscr, h: int, w: int, lw: int) -> None:
        ri    = w - lw - 2
        col   = lw
        MINE  = curses.color_pair(CP_ME) | curses.A_BOLD

        prompt = f" {self.my_nick.upper()}► "
        full   = prompt + self.input_buf
        display = full[-(ri + 1):]
        _safe(stdscr, h - 2, col, display.ljust(ri + 1)[:ri + 1], MINE)

        cx = min(col + len(prompt) + len(self.input_buf), col + ri)
        try:
            stdscr.move(h - 2, cx)
        except curses.error:
            pass


    def _draw(self, stdscr, h: int, w: int) -> None:
        lw = min(LEFT_W, w // 3)     # shrink gracefully on narrow terminals

        self._draw_header(stdscr, h, w)
        self._draw_frame(stdscr, h, w, lw)
        self._draw_titles(stdscr, h, w, lw)
        self._draw_contacts(stdscr, h, w, lw)

        if self.state == CHATTING:
            self._draw_messages(stdscr, h, w, lw)
        else:
            self._draw_standby(stdscr, h, w, lw)

        self._draw_input(stdscr, h, w, lw)


    def _main(self, stdscr) -> None:
        self._setup_colors()
        curses.curs_set(1)
        stdscr.nodelay(True)
        stdscr.keypad(True)
        self._start_pinger()

        while self._running:
            self._drain()
            h, w = stdscr.getmaxyx()

            if w < MIN_W or h < MIN_H:
                stdscr.erase()
                _safe(stdscr, h // 2, 0,
                      f" TERMINAL TOO SMALL ({w}x{h}) — NEED {MIN_W}x{MIN_H} ",
                      curses.color_pair(CP_ERR) | curses.A_BOLD)
                stdscr.refresh()
                curses.napms(250)
                continue

            stdscr.erase()
            self._draw(stdscr, h, w)
            stdscr.refresh()

            try:
                ch = stdscr.get_wch()
            except curses.error:
                curses.napms(30)
                continue

            msg_rows = h - 7
            self._handle_key(ch, msg_rows)

        self._pinger_stop.set()

        h, w = stdscr.getmaxyx()
        stdscr.erase()
        msg = " ░ SESSION ENDED — PRESS ANY KEY ░ "
        _safe(stdscr, h // 2, max(0, (w - len(msg)) // 2), msg,
              curses.color_pair(CP_HDR) | curses.A_BOLD)
        stdscr.refresh()
        stdscr.nodelay(False)
        try:
            stdscr.getch()
        except (curses.error, KeyboardInterrupt):
            pass
