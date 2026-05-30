#!/usr/bin/env python3
import asyncio
import json
import sys
import websockets
from aioice import Candidate, Connection


async def apply_remote_sdp(conn, sdp):
    ufrag = None
    pwd = None
    for line in sdp.splitlines():
        line = line.strip()
        if line.startswith("a=ice-ufrag:"):
            ufrag = line.split(":", 1)[1]
        elif line.startswith("a=ice-pwd:"):
            pwd = line.split(":", 1)[1]
        elif line.startswith("a=candidate:"):
            c = Candidate.from_sdp(line[2:])
            await conn.add_remote_candidate(c)

    if ufrag is not None:
        conn.remote_username = ufrag
    if pwd is not None:
        conn.remote_password = pwd
    await conn.add_remote_candidate(None)


def build_sdp(conn):
    lines = [
        "v=0",
        "o=- 0 0 IN IP4 0.0.0.0",
        "s=-",
        "t=0 0",
        f"a=ice-ufrag:{conn.local_username}",
        f"a=ice-pwd:{conn.local_password}",
    ]
    for c in conn.local_candidates:
        lines.append("a=candidate:" + c.to_sdp())
    return "\r\n".join(lines) + "\r\n"


async def main(server="ws://localhost:18080", room="default"):
    url = f"{server}/{room}"
    async with websockets.connect(url) as ws:
        msg = json.loads(await ws.recv())
        role = msg["role"]
        is_offerer = role == "offerer"
        print(f"Role: {role}")

        conn = Connection(ice_controlling=is_offerer, components=1,
                          stun_server=("14.29.112.241", 20002),
                          use_ipv6=False)

        await conn.gather_candidates()

        local_sdp = build_sdp(conn)
        print(f"Local candidates: {len(conn.local_candidates)}")

        sdp_msg = json.dumps({"type": "sdp", "sdp": local_sdp})
        if is_offerer:
            print("Sending SDP offer...")
            await ws.send(sdp_msg)
            resp = json.loads(await ws.recv())
        else:
            resp = json.loads(await ws.recv())
            print("Received SDP offer, sending answer...")
            await ws.send(sdp_msg)

        await apply_remote_sdp(conn, resp["sdp"])

        print("Starting connectivity checks...")
        try:
            await asyncio.wait_for(conn.connect(), timeout=30)
        except asyncio.TimeoutError:
            print("ICE connect timed out")
            await conn.close()
            return

        if conn._nominated:
            print("ICE connected!")
        else:
            print(f"ICE failed: state={conn._check_list_state}")
            await conn.close()
            return

        recv_count = [0]  # mutable counter for closure

        async def receiver():
            while True:
                try:
                    data = await asyncio.wait_for(conn.recv(), timeout=60)
                except asyncio.TimeoutError:
                    break
                except Exception:
                    break
                recv_count[0] += 1
                if len(data) > 1 and data[0] == 0x10:
                    payload = data[1:].decode(errors="replace")
                else:
                    payload = data.decode(errors="replace")
                print(f"[{recv_count[0]}] {payload}")

        recv_task = asyncio.create_task(receiver())

        label = "Python offerer#" if is_offerer else "Python answerer#"
        for i in range(1, 31):
            await asyncio.sleep(1)
            try:
                await conn.send(b"\x10" + (label + str(i)).encode())
            except Exception as e:
                print(f"Send error: {e}")
                break

        recv_task.cancel()
        try:
            await recv_task
        except asyncio.CancelledError:
            pass

        await conn.close()
        print("Done.")


if __name__ == "__main__":
    asyncio.run(main())
