#!/usr/bin/env python3
"""aiortc DataChannel ping-pong demo with asio-ice."""

import asyncio
import json
import sys
import websockets
from aiortc import RTCPeerConnection, RTCSessionDescription, RTCIceCandidate
from aioice import Candidate as IceCandidate


def make_rtc_candidate(cand_str):
    c = IceCandidate.from_sdp(cand_str)
    return RTCIceCandidate(
        component=c.component,
        foundation=c.foundation,
        ip=c.host,
        port=c.port,
        priority=c.priority,
        protocol=c.transport,
        type=c.type,
        relatedAddress=c.related_address,
        relatedPort=c.related_port,
        sdpMLineIndex=0,
    )


async def main(server="ws://localhost:8080/ws"):
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
            await asyncio.sleep(1)
            channel.send('ping')

    @pc.on("iceconnectionstatechange")
    async def on_ice_state():
        print(f"ICE state: {pc.iceConnectionState}")
        if pc.iceConnectionState in ("connected", "completed",
                                       "failed", "disconnected"):
            pc_complete.set()

    @pc.on("icecandidate")
    def on_icecandidate(candidate):
        if candidate:
            cand_str = (
                candidate.candidate
                if hasattr(candidate, "candidate") and candidate.candidate
                else ""
            )
            asyncio.ensure_future(
                ws.send(
                    json.dumps(
                        {"type": "candidate", "candidate": cand_str}
                    )
                )
            )

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

    while not pc_complete.is_set():
        await asyncio.sleep(1)
    print(f"Final ICE state: {pc.iceConnectionState}")

    while True:
        await asyncio.sleep(5)
        print("Waiting for pong...")

    await pc.close()
    await ws.close()


if __name__ == "__main__":
    asyncio.run(main())
