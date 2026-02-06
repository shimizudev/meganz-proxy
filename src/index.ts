import { Elysia } from "elysia";
import { cors } from "@elysiajs/cors";
import { CloudflareAdapter } from "elysia/adapter/cloudflare-worker";

interface MegaStreamData {
  encryptedUrl: string;
  aesKey: Buffer;
  nonce: Buffer;
  fileName: string;
  fileSize: number;
}

export default new Elysia({
  adapter: CloudflareAdapter,
})
  .use(cors())
  .get("/", () => ({
    message: "Mega Video Stream API",
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

    const info = await getMegaDownloadInfo(megaUrl);
    const baseUrl = new URL(request.url).origin;

    return {
      fileName: info.fileName,
      fileSize: info.fileSize,
      streamUrl: `${baseUrl}/stream?url=${encodeURIComponent(megaUrl)}`,
    };
  })
  .get("/stream", async ({ query, request, set }) => {
    const { url: megaUrl } = query;

    if (!megaUrl) {
      set.status = 400;
      return { error: "Missing url parameter" };
    }

    const info = await getMegaDownloadInfo(megaUrl);

    // Handle range requests
    const range = request.headers.get("Range");
    let startByte = 0;
    let endByte = info.fileSize - 1;

    if (range) {
      const parts = range.replace(/bytes=/, "").split("-");
      startByte = parseInt(parts[0] as string, 10);
      endByte = parts[1] ? parseInt(parts[1], 10) : endByte;
    }

    // Fetch encrypted stream
    const headers: Record<string, string> = {};
    if (range) {
      headers["Range"] = `bytes=${startByte}-${endByte}`;
    }

    const encryptedResponse = await fetch(info.encryptedUrl, { headers });

    // Setup decryption
    const crypto = await import("node:crypto");
    const blockOffset = Math.floor(startByte / 16);
    const intraBlockOffset = startByte % 16;

    const counter = Buffer.alloc(16);
    info.nonce.copy(counter, 0);
    counter.writeBigUInt64BE(BigInt(blockOffset), 8);

    const decipher = crypto.createDecipheriv(
      "aes-128-ctr",
      info.aesKey,
      counter,
    );

    // Create readable stream
    const readable = new ReadableStream({
      async start(controller) {
        if (!encryptedResponse.body) return;

        const reader = encryptedResponse.body.getReader();
        let isFirstChunk = true;

        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            let decrypted = decipher.update(value);

            // Handle intra-block offset
            if (isFirstChunk && intraBlockOffset > 0) {
              decrypted = decrypted.subarray(intraBlockOffset);
              isFirstChunk = false;
            }

            controller.enqueue(decrypted);
          }
          controller.close();
        } catch (error) {
          controller.error(error);
        }
      },
    });

    // Set response headers
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

    // @ts-expect-error
    return new Response(readable, { headers: set.headers });
  })
  .compile();

async function getMegaDownloadInfo(megaUrl: string): Promise<MegaStreamData> {
  const decodedUrl = decodeURIComponent(atob(megaUrl));
  const match = decodedUrl.match(/mega\.nz\/(?:file\/|#!)([^#!]+)[#!](.+)/);
  if (!match) throw new Error("Invalid Mega URL");

  const [, handle, key] = match as [unknown, string, string];

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
  const megaData = data[0]!;

  const nodeKey = base64UrlDecode(key);
  const { aesKey, nonce } = unpackNodeKey(nodeKey);
  const fileName = await decryptAttributes(megaData.at, aesKey);

  return {
    encryptedUrl: megaData.g,
    aesKey,
    nonce,
    fileName,
    fileSize: megaData.s,
  };
}

function base64UrlDecode(str: string): Buffer {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) base64 += "=";
  return Buffer.from(base64, "base64");
}

function unpackNodeKey(nodeKey: Buffer) {
  const aesKey = Buffer.alloc(16);
  for (let i = 0; i < 4; i++) {
    const offset = i * 4;
    aesKey.writeUInt32BE(
      nodeKey.readUInt32BE(offset) ^ nodeKey.readUInt32BE(offset + 16),
      offset,
    );
  }
  const nonce = nodeKey.subarray(16, 24);
  return { aesKey, nonce };
}

async function decryptAttributes(
  encryptedAttrs: string,
  key: Buffer,
): Promise<string> {
  const crypto = await import("node:crypto");
  const ciphertext = base64UrlDecode(encryptedAttrs);
  const iv = Buffer.alloc(16, 0);

  const decipher = crypto.createDecipheriv("aes-128-cbc", key, iv);
  decipher.setAutoPadding(false);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  const str = decrypted.toString("utf8").replace(/\0+$/, "");

  const json = JSON.parse(str.substring(4));
  return json.n || "download";
}
