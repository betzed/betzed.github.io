(function () {
  class SeedNum {
    constructor(serverBytes, client, nonce) {
      this._client = client;
      this._nonce = nonce;
      this._keyBytes = Uint8Array.from(serverBytes);
      this._cryptoKeyPromise = this.importKey(this._keyBytes);
      this._count = 0;
      this._rng = new Uint8Array();
    }

    async getNextNumber(maxValue) {
      if (this._count % 8 === 0) {
        const message = `${this._client}:${this._nonce}:${Math.floor(
          this._count / 8
        )}`;
        this._rng = await this.hmacSha256(
          await this._cryptoKeyPromise,
          message
        );
      }
      const idx = this._count % 8;

      /**
       * NOTE:
       * - old version (RNG_VERSION 0) has issue of re-used bytes
       * - new version (RNG_VERSION > 0) fixed the issue by multiplying idx with 4 to get correct byte offset
       * - affected games that use more than 1 times of getNextNumber()
       */
      const number =
        window.RNG_VERSION === 0
          ? this.bytesToUint32(this._rng.slice(idx, idx + 4))
          : this.bytesToUint32(this._rng.slice(idx * 4, idx * 4 + 4));

      this._count++;
      const maxUInt = 0xffffffff;

      // get next number to prevent modulo bias
      if (number >= maxUInt - (maxUInt % maxValue))
        return this.getNextNumber(maxValue);

      return number % maxValue;
    }

    async get4BytesNumber() {
      if (this._rng.length === 0) await this.getNextNumber(1);
      let num = 0;
      for (let i = 0; i < 4; i++) num += this._rng[i] / Math.pow(256, i + 1);
      return num;
    }

    // get a random element (without removal)
    async getItem(list) {
      const idx = await this.getNextNumber(list.length);
      return list[idx];
    }

    // pick and remove a random element
    async pickItem(list) {
      const idx = await this.getNextNumber(list.length);
      const item = list[idx];
      list.splice(idx, 1);
      return item;
    }

    async importKey(rawKey) {
      return crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
    }

    async hmacSha256(key, message) {
      const enc = new TextEncoder();
      const msgBytes = enc.encode(message);
      const signature = await crypto.subtle.sign("HMAC", key, msgBytes);
      return new Uint8Array(signature);
    }

    bytesToUint32(bytes) {
      return (
        (bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24)) >>> 0
      );
    }
  }

  window.SeedNum = SeedNum;

  // utils methods
  window.hexToUint8Array = function (hex) {
    if (typeof hex !== "string") {
      throw new TypeError("Expected a string");
    }

    // Remove 0x prefix if present
    if (hex.startsWith("0x")) {
      hex = hex.slice(2);
    }

    if (hex.length % 2 !== 0) {
      throw new Error("Invalid hex string length");
    }

    const array = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      array[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return array;
  };

  window.uint8ArrayToHex = function (uint8Array) {
    return Array.from(uint8Array)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  };

  // default rtp
  window.RTP = 0.98;

  // initialize fields
  const params = new URLSearchParams(window.location.search);

  // default RNG_VERSION to latest version (1)
  const rngVersion = parseInt(params.get("rng"));
  window.RNG_VERSION = isNaN(rngVersion) ? 1 : rngVersion;

  // init default fields
  document.getElementById("server").value = params.get("server") || "";
  document.getElementById("client").value = params.get("client") || "";
  document.getElementById("nonce").value = params.get("nonce") || "";
  document.getElementById("count")?.setAttribute("value", params.get("count"));
})();
