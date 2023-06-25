import nacl from "tweetnacl";
import test from "ava";
import type {
  APIInteractionResponsePong,
  APIPingInteraction,
} from "discord-api-types/v9";
import {
  INTERACTION,
  algorithm,
  dispatchInteraction,
  encoder,
  ignite,
  key,
} from "./helpers";

test("responds with PONG", async (t) => {
  const mf = ignite(t);
  const interaction: APIPingInteraction = { ...INTERACTION, type: 1 }; // 1 = InteractionType.PING
  const res = await dispatchInteraction(mf, interaction);
  t.is(res.status, 200);
  const body = await res.json<APIInteractionResponsePong>();
  t.deepEqual(body, { type: 1 }); // 1 = InteractionResponseType.PONG
});

test("responds with 401 if signature validation fails", async (t) => {
  const mf = ignite(t);
  const interaction: APIPingInteraction = { ...INTERACTION, type: 1 }; // 1 = InteractionType.PING
  const jsonBody = JSON.stringify(interaction);

  // Try without any signature
  let res = await mf.dispatchFetch("http://localhost:8787", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: jsonBody,
  });
  t.is(res.status, 401);
  t.is(await res.text(), "Unauthorized");

  // Try with a bad signature
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const message = encoder.encode(timestamp + jsonBody + "😈");
  const signature = nacl.sign.detached(message, key.privateKey);
  const signatureHex = Buffer.from(signature).toString("hex");
  res = await mf.dispatchFetch("http://localhost:8787", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Signature-Ed25519": signatureHex,
      "X-Signature-Timestamp": timestamp,
    },
    body: jsonBody,
  });
  t.is(res.status, 401);
  t.is(await res.text(), "Unauthorized");
});
