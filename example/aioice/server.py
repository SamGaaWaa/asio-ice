#!/usr/bin/env python3
import asyncio
import json
import sys
import websockets
from collections import deque

PEERS = {}
BUFFERS = {}


async def handler(ws):
    path = ws.path
    room = path.strip("/") or "default"
    print(f"New connection from {ws.remote_address} to room '{room}'")

    if room not in PEERS:
        PEERS[room] = [ws, None]
        BUFFERS[room] = deque()
        role = "offerer"
    elif PEERS[room][1] is None:
        PEERS[room][1] = ws
        role = "answerer"
    else:
        await ws.close(1000, "Room full")
        return

    peer_list = PEERS[room]
    buf = BUFFERS[room]

    try:
        await ws.send(json.dumps({"type": "role", "role": role}))

        if role == "answerer":
            while buf:
                await ws.send(buf.popleft())

        async for msg_text in ws:
            target = peer_list[1] if role == "offerer" else peer_list[0]
            if target:
                await target.send(msg_text)
            else:
                buf.append(msg_text)
    except Exception:
        pass
    finally:
        if role == "offerer":
            if peer_list[1]:
                try:
                    await peer_list[1].close(1000, "Peer disconnected")
                except Exception:
                    pass
            PEERS.pop(room, None)
            BUFFERS.pop(room, None)
        else:
            peer_list[1] = None


async def main(port=18080):
    print(f"Signaling server starting on port {port}...")
    async with websockets.serve(handler, "0.0.0.0", port):
        print(f"Listening on ws://0.0.0.0:{port}")
        await asyncio.get_running_loop().create_future()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18080
    asyncio.run(main(port))
