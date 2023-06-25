import type {
  APIInteraction,
  APIModalSubmitInteraction,
} from "discord-api-types/v9";
import nacl from "tweetnacl";
import { hexDecode } from "../helpers";

const ENCODER = /* @__PURE__ */ new TextEncoder();

export async function validateInteraction(
  publicKeyData: Uint8Array,
  request: Request
): Promise<APIInteraction | APIModalSubmitInteraction | false> {
  const signature = hexDecode(
    String(request.headers.get("X-Signature-Ed25519"))
  );

  const timestamp = String(request.headers.get("X-Signature-Timestamp"));
  const body = await request.text();

  const valid = nacl.sign.detached.verify(
    ENCODER.encode(timestamp + body),
    signature,
    publicKeyData
  );

  return valid && JSON.parse(body);
}
