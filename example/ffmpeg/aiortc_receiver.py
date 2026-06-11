#!/usr/bin/env python3
"""aiortc SRTP receiver — receives video stream from asio-ice ffmpeg example."""

import asyncio
import json
import sys
import websockets
from aiortc import (
    RTCPeerConnection,
    RTCSessionDescription,
    RTCIceCandidate,
)
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
    frame_count = [0]

    pc.addTransceiver("video", direction="recvonly")
    print("Added video transceiver (recvonly)")

    @pc.on("track")
    def on_track(track):
        print(f"Track received: {track.kind}")
        asyncio.ensure_future(consume_track(track, frame_count))

    @pc.on("iceconnectionstatechange")
    async def on_ice_state():
        state = pc.iceConnectionState
        print(f"ICE state: {state}")
        if state in ("connected", "completed", "failed", "disconnected"):
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
    while not pc_complete.is_set():
        await asyncio.sleep(1)
    print(f"Final ICE state: {pc.iceConnectionState}")

    print("Waiting for video frames...")
    await asyncio.sleep(15)
    print(f"Frames received: {frame_count[0]}")

    await pc.close()
    await ws.close()


async def consume_track(track, counter):
    print(f"Consuming track: {track.kind}")
    while True:
        try:
            frame = await track.recv()
            counter[0] += 1
            if counter[0] == 1:
                print(
                    f"First frame: {frame.width}x{frame.height}, "
                    f"pts={frame.pts}, time={frame.time}"
                )
            elif counter[0] % 30 == 0:
                print(f"Frames received: {counter[0]}")
        except Exception as e:
            print(f"Track recv ended: {e}")
            break


if __name__ == "__main__":
    asyncio.run(main())
