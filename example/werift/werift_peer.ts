// werift-webrtc DataChannel ping-pong demo with asio-ice.
// Usage: npx tsx werift_peer.ts [ws://localhost:8082/ws]

import { RTCPeerConnection } from "werift";
import WebSocket from "ws";

const SERVER = process.argv[2] ?? "ws://localhost:8082/ws";

async function main() {
    const ws = new WebSocket(SERVER);

    await new Promise<void>((resolve, reject) => {
        ws.on("open", resolve);
        ws.on("error", reject);
    });
    console.log("Connected to signaling server");

    const pc = new RTCPeerConnection({});
    let iceComplete: () => void;
    const iceDone = new Promise<void>((resolve) => {
        iceComplete = resolve;
    });

    let firstState = true;
    pc.iceConnectionStateChange.subscribe((state) => {
        console.log(`ICE state: ${state}`);
        if (firstState) {
            firstState = false;
            return;
        }
        if (state === "connected" || state === "completed" ||
            state === "failed" || state === "disconnected" ||
            state === "closed") {
            iceComplete();
        }
    });

    const dc = pc.createDataChannel("pingpong");
    console.log(`Created data channel: ${dc.label}`);

    dc.onopen = () => {
        console.log('DataChannel "pingpong" OPEN!');
        dc.send("ping");
        console.log("Sent: ping");
    };

    let pongReceived: () => void;
    const pongDone = new Promise<void>((resolve) => {
        pongReceived = resolve;
    });

    dc.onmessage = (e) => {
        const text = e.data as string;
        console.log(`Received on '${dc.label}': ${text}`);
        if (text === "pong") {
            console.log("Ping-pong SUCCESS!");
            pongReceived();
        }
    };

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);

    await new Promise<void>((resolve) => {
        if (pc.iceGatheringState === "complete") {
            resolve();
        } else {
            const { unSubscribe } = pc.iceGatheringStateChange.subscribe(
                (state) => {
                    if (state === "complete") {
                        unSubscribe();
                        resolve();
                    }
                }
            );
        }
    });

    console.log("Sending SDP offer");
    ws.send(JSON.stringify({
        type: "offer",
        sdp: pc.localDescription!.sdp,
    }));

    const msg: any = await new Promise((resolve) => {
        ws.on("message", (data) => {
            resolve(JSON.parse(data.toString()));
        });
    });
    console.log("Got SDP answer");
    await pc.setRemoteDescription({
        type: "answer",
        sdp: msg.sdp,
    } as any);

    console.log("Waiting for ICE connection...");
    await Promise.race([
        iceDone,
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error("ICE connection timeout")), 60000)
        ),
    ]);

    const finalState = pc.iceConnectionState;
    console.log(`Final ICE state: ${finalState}`);

    if (finalState !== "connected" && finalState !== "completed") {
        console.error("ICE did not connect successfully");
        process.exit(1);
    }

    console.log("Waiting for pong...");
    await Promise.race([
        pongDone,
        new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Pong timeout")), 60000)
        ),
    ]);
    console.log("Done!");

    pc.close();
    ws.close();
    process.exit(0);
}

main().catch((err) => {
    console.error(err);
    process.exit(1);
});
