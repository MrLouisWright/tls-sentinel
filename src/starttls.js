// STARTTLS negotiation before the TLS handshake: SMTP, IMAP, POP3, FTP, PostgreSQL.
import net from 'node:net';

export const STARTTLS_PORTS = { smtp: 587, smtps: 465, imap: 143, pop3: 110, ftp: 21, postgres: 5432 };

function lines(sock, timeout) {
  let buf = ''; const waiters = [];
  sock.on('data', (d) => { buf += d.toString('latin1'); flush(); });
  const flush = () => { while (waiters.length) { const w = waiters[0]; const m = w.re.exec(buf); if (!m) return; buf = buf.slice(m.index + m[0].length); waiters.shift(); clearTimeout(w.t); w.ok(m[0]); } };
  return (re) => new Promise((ok, fail) => { const w = { re, ok, t: setTimeout(() => fail(new Error(`STARTTLS: timed out waiting for ${re}`)), timeout) }; waiters.push(w); flush(); });
}

/** Open a plain TCP connection and run the protocol's STARTTLS dialog. Resolves the socket, ready for tls.connect({ socket }). */
export function negotiate(protocol, { host, port, timeout = 10000, ehloName = 'tls-sentinel.invalid' }) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port });
    const t = setTimeout(() => { sock.destroy(); reject(new Error(`timeout after ${timeout} ms`)); }, timeout);
    sock.once('error', (e) => { clearTimeout(t); reject(e); });
    sock.once('connect', async () => {
      try {
        const wait = lines(sock, timeout);
        const send = (s) => sock.write(s);
        if (protocol === 'smtp') {
          const greet = await wait(/^(\d{3})[ ][^\r\n]*\r?\n/m); if (!greet.startsWith('220')) throw new Error(`SMTP greeting: ${greet.trim()}`);
          send(`EHLO ${ehloName}\r\n`); const ehlo = await waitMulti(wait); if (!/STARTTLS/i.test(ehlo)) throw new Error('server does not offer STARTTLS');
          send('STARTTLS\r\n'); const r = await wait(/^\d{3}[ ][^\r\n]*\r?\n/m); if (!r.startsWith('220')) throw new Error(`STARTTLS refused: ${r.trim()}`);
        } else if (protocol === 'imap') {
          await wait(/^\* (OK|PREAUTH)[^\r\n]*\r?\n/m); send('a1 STARTTLS\r\n'); const r = await wait(/^a1 (OK|NO|BAD)[^\r\n]*\r?\n/m); if (!/^a1 OK/.test(r)) throw new Error(`STARTTLS refused: ${r.trim()}`);
        } else if (protocol === 'pop3') {
          await wait(/^\+OK[^\r\n]*\r?\n/m); send('STLS\r\n'); const r = await wait(/^(\+OK|-ERR)[^\r\n]*\r?\n/m); if (!r.startsWith('+OK')) throw new Error(`STLS refused: ${r.trim()}`);
        } else if (protocol === 'ftp') {
          await wait(/^220[ ][^\r\n]*\r?\n/m); send('AUTH TLS\r\n'); const r = await wait(/^\d{3}[ ][^\r\n]*\r?\n/m); if (!r.startsWith('234')) throw new Error(`AUTH TLS refused: ${r.trim()}`);
        } else if (protocol === 'postgres') {
          const req = Buffer.alloc(8); req.writeUInt32BE(8, 0); req.writeUInt32BE(80877103, 4); send(req);
          const r = await new Promise((ok) => sock.once('data', (d) => ok(d))); if (r[0] !== 0x53) throw new Error(`PostgreSQL refused SSL (${String.fromCharCode(r[0])})`);
        } else throw new Error(`unknown STARTTLS protocol ${protocol}`);
        clearTimeout(t); sock.removeAllListeners('data'); resolve(sock);
      } catch (e) { clearTimeout(t); sock.destroy(); reject(e); }
    });
  });
}
async function waitMulti(wait) { let all = ''; for (;;) { const l = await wait(/^\d{3}[- ][^\r\n]*\r?\n/m); all += l; if (/^\d{3} /.test(l)) return all; } }
