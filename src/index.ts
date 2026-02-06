import { Elysia } from "elysia";
import { cors } from "@elysiajs/cors";
import { CloudflareAdapter } from "elysia/adapter/cloudflare-worker";
import aesjs from "aes-js";

interface MegaStreamData {
  encryptedUrl: string;
  aesKey: Uint8Array;
  nonce: Uint8Array;
  fileName: string;
  fileSize: number;
}

export default new Elysia({
  adapter: CloudflareAdapter,
})
  .use(cors())
  .get("/", () => ({
    message: "Mega Video Stream API (CF Worker)",
    endpoints: {
      info: "/api/info?url=<mega_url>",
      stream: "/stream?url=<mega_url>",
    },
  }))
  .get("/api/info", async ({ query, request }) => {
    const { url: megaUrl } = query;

    if (!megaUrl) {
      return { error: "Missing url parameter" };
    }

    try {
      const info = await getMegaDownloadInfo(megaUrl);
      const baseUrl = new URL(request.url).origin;

      return {
        fileName: info.fileName,
        fileSize: info.fileSize,
        streamUrl: `${baseUrl}/stream?url=${encodeURIComponent(megaUrl)}`,
      };
    } catch (e) {
      return { error: (e as Error).message };
    }
  })
  .get("/stream", async ({ query, request, set }) => {
    const { url: megaUrl } = query;

    if (!megaUrl) {
      set.status = 400;
      return { error: "Missing url parameter" };
    }

    try {
      const info = await getMegaDownloadInfo(megaUrl);

      // 1. Handle Range Requests
      const range = request.headers.get("Range");
      let startByte = 0;
      let endByte = info.fileSize - 1;

      if (range) {
        const parts = range.replace(/bytes=/, "").split("-");
        startByte = parseInt(parts[0] as string, 10);
        endByte = parts[1] ? parseInt(parts[1], 10) : endByte;
      }

      // 2. Align Request to AES Block Size (16 bytes)
      const blockAlignedStart = Math.floor(startByte / 16) * 16;
      const intraBlockOffset = startByte - blockAlignedStart;

      const headers: Record<string, string> = {};
      headers["Range"] = `bytes=${blockAlignedStart}-${endByte}`;

      const encryptedResponse = await fetch(info.encryptedUrl, { headers });

      if (!encryptedResponse.body) {
        throw new Error("No response body from Mega");
      }

      // 3. Prepare Web Crypto Key for CTR (Streaming)
      // @ts-expect-error
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        info.aesKey,
        { name: "AES-CTR" },
        false,
        ["decrypt"],
      );

      // 4. Transform Stream (Decrypt on the fly)
      let currentBlockIndex = BigInt(blockAlignedStart / 16);
      let isFirstChunk = true;
      let buffer = new Uint8Array(0);

      const transformer = new TransformStream({
        async transform(chunk, controller) {
          const newBuffer = new Uint8Array(buffer.length + chunk.length);
          newBuffer.set(buffer);
          newBuffer.set(chunk, buffer.length);
          buffer = newBuffer;

          const processableLength = Math.floor(buffer.length / 16) * 16;

          if (processableLength > 0) {
            const toDecrypt = buffer.slice(0, processableLength);
            buffer = buffer.slice(processableLength);

            const counterBlock = new Uint8Array(16);
            counterBlock.set(info.nonce, 0);
            const view = new DataView(counterBlock.buffer);
            view.setBigUint64(8, currentBlockIndex, false);

            const decryptedBuffer = await crypto.subtle.decrypt(
              {
                name: "AES-CTR",
                counter: counterBlock,
                length: 64,
              },
              cryptoKey,
              toDecrypt,
            );

            let decrypted = new Uint8Array(decryptedBuffer);

            if (isFirstChunk && intraBlockOffset > 0) {
              decrypted = decrypted.slice(intraBlockOffset);
              isFirstChunk = false;
            } else {
              isFirstChunk = false;
            }

            controller.enqueue(decrypted);
            currentBlockIndex += BigInt(processableLength / 16);
          }
        },
        async flush(controller) {
          if (buffer.length > 0) {
            const counterBlock = new Uint8Array(16);
            counterBlock.set(info.nonce, 0);
            const view = new DataView(counterBlock.buffer);
            view.setBigUint64(8, currentBlockIndex, false);

            const decryptedBuffer = await crypto.subtle.decrypt(
              {
                name: "AES-CTR",
                counter: counterBlock,
                length: 64,
              },
              cryptoKey,
              buffer,
            );

            let decrypted = new Uint8Array(decryptedBuffer);

            if (isFirstChunk && intraBlockOffset > 0) {
              decrypted = decrypted.slice(intraBlockOffset);
            }

            controller.enqueue(decrypted);
          }
        },
      });

      set.headers["Content-Type"] = "video/mp4";
      set.headers["Accept-Ranges"] = "bytes";

      if (range) {
        set.status = 206;
        set.headers["Content-Range"] =
          `bytes ${startByte}-${endByte}/${info.fileSize}`;
        set.headers["Content-Length"] = String(endByte - startByte + 1);
      } else {
        set.headers["Content-Length"] = String(info.fileSize);
      }

      return new Response(encryptedResponse.body.pipeThrough(transformer), {
        // @ts-expect-error
        headers: set.headers,
        // @ts-expect-error
        status: set.status,
      });
    } catch (e) {
      set.status = 500;
      return { error: (e as Error).message };
    }
  })
  .compile();

async function getMegaDownloadInfo(megaUrl: string): Promise<MegaStreamData> {
  const decodedUrl = decodeURIComponent(atob(megaUrl));
  const match = decodedUrl.match(/mega\.nz\/(?:file\/|#!)([^#!]+)[#!](.+)/);
  if (!match) throw new Error("Invalid Mega URL");

  const [, handle, key] = match;

  const response = await fetch("https://g.api.mega.co.nz/cs?id=0", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify([{ a: "g", g: 1, ssl: 0, p: handle }]),
  });

  const data = (await response.json()) as {
    at: string;
    g: string;
    s: number;
  }[];

  if (!data[0]) throw new Error("File not found or deleted");
  const megaData = data[0];

  if (!key) throw new Error("Key is not available in the mega url.");

  const nodeKey = base64UrlToUint8Array(key);
  const { aesKey, nonce } = unpackNodeKey(nodeKey);

  const fileName = decryptAttributes(megaData.at, aesKey);

  return {
    encryptedUrl: megaData.g,
    aesKey,
    nonce,
    fileName,
    fileSize: megaData.s,
  };
}

function base64UrlToUint8Array(str: string): Uint8Array {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(
    base64.length + ((4 - (base64.length % 4)) % 4),
    "=",
  );
  const binaryString = atob(padded);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

function unpackNodeKey(nodeKey: Uint8Array) {
  const view = new DataView(nodeKey.buffer);
  const aesKey = new Uint8Array(16);
  const aesView = new DataView(aesKey.buffer);

  for (let i = 0; i < 4; i++) {
    const offset = i * 4;
    const n1 = view.getUint32(offset, false);
    const n2 = view.getUint32(offset + 16, false);
    aesView.setUint32(offset, n1 ^ n2, false);
  }

  const nonce = nodeKey.slice(16, 24);
  return { aesKey, nonce };
}

function decryptAttributes(encryptedAttrs: string, key: Uint8Array): string {
  const ciphertext = base64UrlToUint8Array(encryptedAttrs);
  const iv = new Uint8Array(16).fill(0);

  // @ts-ignore - aes-js types might mismatch slightly with esm import but it works at runtime
  const aesCbc = new aesjs.ModeOfOperation.cbc(key, iv);

  const decryptedBytes = aesCbc.decrypt(ciphertext);

  let end = decryptedBytes.length;
  while (end > 0 && decryptedBytes[end - 1] === 0) {
    end--;
  }

  const jsonStr = new TextDecoder().decode(decryptedBytes.slice(0, end));

  const json = JSON.parse(jsonStr.substring(4));
  return json.n || "download.mp4";
}
