#!/usr/bin/env python3
"""Python peer for asio-ice pion example using aiortc."""

import asyncio
import json
import sys
import websockets
from aiortc import RTCPeerConnection, RTCSessionDescription


async def main(server="ws://localhost:8081/ws"):
    ws = await websockets.connect(server)
    print("Connected to signaling server")

    pc = RTCPeerConnection()
    pc_complete = asyncio.Event()

    channel = pc.createDataChannel("pingpong")
    print(f"Created data channel: {channel.label}")

    @channel.on("open")
    def on_open():
        print("DataChannel 'pingpong' OPEN!")
        channel.send("ping")
        print("Sent: ping")

    @channel.on("message")
    async def on_message(message):
        print(f"Received on '{channel.label}': {message}")
        if message == "pong":
            print("Ping-pong SUCCESS!")

    @pc.on("iceconnectionstatechange")
    async def on_ice_state():
        print(f"ICE state: {pc.iceConnectionState}")
        if pc.iceConnectionState in ("connected", "completed",
                                       "failed", "disconnected"):
            pc_complete.set()

    offer = await pc.createOffer()
    await pc.setLocalDescription(offer)
    print("Sending SDP offer")
    await ws.send(
        json.dumps({"type": "offer", "sdp": pc.localDescription.sdp})
    )

    msg = await ws.recv()
    msg = json.loads(msg)
    print("Got SDP answer")
    await pc.setRemoteDescription(
        RTCSessionDescription(sdp=msg["sdp"], type="answer")
    )

    print("Waiting for ICE connection...")
    try:
        await asyncio.wait_for(pc_complete.wait(), timeout=30)
    except asyncio.TimeoutError:
        print("ICE connection timeout")
        return

    final_state = pc.iceConnectionState
    print(f"Final ICE state: {final_state}")

    if final_state not in ("connected", "completed"):
        print("ICE did not connect successfully")
        return

    print("Waiting for pong...")
    try:
        await asyncio.wait_for(asyncio.sleep(30), timeout=30)
    except asyncio.TimeoutError:
        pass

    await pc.close()
    await ws.close()


if __name__ == "__main__":
    asyncio.run(main())
