function getSignature(token, timestamp, nonce, encryptedMsg) {
  try {
    const str = [token, timestamp, nonce, encryptedMsg];
    str.sort();
    var s = str.join("");
    return CryptoJS.SHA256(s).toString();
  } catch (err) {
    console.error(err.message);
  }
}

function PKCS7Encode(length) {
  var amountPad = 32 - (length % 32);
  if (amountPad == 0) {
    amountPad = 32;
  }
  var padChr = String.fromCharCode(amountPad);
  var tmpData = "";
  for (var i = 0; i < amountPad; i++) {
    tmpData += padChr;
  }
  return tmpData;
}

function PKCS7Decode(decrypted) {
  var padStrArr = CryptoJS.lib.WordArray.create(
    [...decrypted.words].slice(
      decrypted.words.length - 1,
      decrypted.words.length
    )
  );
  var padStr = CryptoJS.enc.Utf8.stringify(padStrArr);
  var pad = padStr.substr(padStr.length - 1, padStr.length).charCodeAt();
  if (pad < 1 || pad > 32) {
    pad = 0;
  }
  const arrPad = Math.ceil(pad / 4);
  padStr = CryptoJS.enc.Utf8.stringify(
    CryptoJS.lib.WordArray.create(
      [...decrypted.words].slice(
        decrypted.words.length - arrPad,
        decrypted.words.length
      )
    )
  );
  const endStr = CryptoJS.enc.Utf8.parse(padStr.substr(0, padStr.length - pad));
  var copyDecrypted = CryptoJS.lib.WordArray.create(
    [...decrypted.words].slice(0, decrypted.words.length - arrPad)
  );
  return copyDecrypted.concat(endStr);
}

function pack(length) {
  var first = CryptoJS.enc.Latin1.parse(
    String.fromCharCode((length >> 24) & 0xff)
  );
  var sencond = CryptoJS.enc.Latin1.parse(
    String.fromCharCode((length >> 16) & 0xff)
  );
  var third = CryptoJS.enc.Latin1.parse(
    String.fromCharCode((length >> 8) & 0xff)
  );
  var forth = CryptoJS.enc.Latin1.parse(String.fromCharCode(length & 0xff));
  first.concat(sencond);
  first.concat(third);
  first.concat(forth);
  return first;
}

function unpack(network) {
  var sourceNumber = 0;
  for (var i = 0; i < 4; i++) {
    sourceNumber <<= 8;
    sourceNumber |= network.substr(i, i + 1).charCodeAt() & 0xff;
  }
  return sourceNumber;
}
export class AesCrypt {
  key;
  constructor(k) {
    this.key = k + "=";
  }
  async encrypt(text, appid) {
    try {
      const random = await this.getRandomStr();
      const appidWA = CryptoJS.enc.Utf8.parse(appid);
      const randomWA = CryptoJS.enc.Utf8.parse(random);
      const textWA = CryptoJS.enc.Utf8.parse(text);
      const packedArr = await pack(textWA.sigBytes);
      randomWA.concat(packedArr);
      randomWA.concat(textWA);
      randomWA.concat(appidWA);
      var dataWA = randomWA;
      // AES require input length not multiple of 16 bytes
      var padData = PKCS7Encode(dataWA.sigBytes);
      const padDataWA = CryptoJS.enc.Utf8.parse(padData);
      dataWA.concat(padDataWA);
      var keyWA = CryptoJS.enc.Base64.parse(this.key);
      // iv = key(0,16)
      const ivWords = [...keyWA.words].splice(0, 4);
      const iv = CryptoJS.lib.WordArray.create(ivWords);
      const encrypted = CryptoJS.AES.encrypt(dataWA, keyWA, {
        iv: iv,
        padding: CryptoJS.pad.NoPadding,
        mode: CryptoJS.mode.CBC,
      });
      return encrypted.toString();
    } catch (err) {
      console.log("AesCrpty err", err.message);
    }
  }
  async decrypt(encrypted, appKey) {
    try {
      var keyWA = CryptoJS.enc.Base64.parse(this.key);
      const ivWords = [...keyWA.words].splice(0, 4);
      const iv = CryptoJS.lib.WordArray.create(ivWords);
      const decryptMsg = CryptoJS.AES.decrypt(encrypted, keyWA, {
        iv: iv,
        padding: CryptoJS.pad.NoPadding,
        mode: CryptoJS.mode.CBC,
      });
      //const ivCiphertext = iv.clone().concat(ciphertext);
      var dataMsg = PKCS7Decode(decryptMsg);
      var network = CryptoJS.enc.Latin1.stringify(
        CryptoJS.lib.WordArray.create([...dataMsg.words].slice(4, 5))
      );
      const dataLength = unpack(network);
      var contentArr = CryptoJS.lib.WordArray.create(
        [...dataMsg.words].slice(5, dataMsg.words.length)
      );
      var contentStr = CryptoJS.enc.Utf8.stringify(contentArr);
      var index = contentStr.indexOf(appKey);
      if (index > -1) {
        contentStr = contentStr.substr(0, index);
      }
      return contentStr;
    } catch (err) {
      console.error(err.message);
    }
  }
  async getRandomStr() {
    let str = "";
    const str_pol =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
    const max = str_pol.length - 1;
    for (let i = 0; i < 16; i++) {
      const r = await this.mtRand(0, max);
      str = str + str_pol[r];
    }
    return str;
  }
  mtRand(min, max) {
    const argc = arguments.length;
    if (argc === 0) {
      min = 0;
      max = 2147483647;
    } else if (argc === 1) {
      throw new Error(
        "Warning: mt_rand() expects exactly 2 parameters, 1 given"
      );
    } else {
      min = parseInt(min, 10);
      max = parseInt(max, 10);
    }
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
}

export class BizMsgCrypt {
  token;
  encodingAesKey;
  appId;
  constructor(token, encodingAesKey, appId) {
    this.token = token;
    if (encodingAesKey.length != 43) {
      throw new Error("invalid aes key");
    }
    this.encodingAesKey = encodingAesKey;
    this.appId = appId;
  }
  async encryptMsg(replyMsg, timestamp, nonce) {
    const ac = new AesCrypt(this.encodingAesKey);
    const encrypt = await ac.encrypt(replyMsg, this.appId);
    const signature = await getSignature(
      this.token,
      timestamp + "",
      nonce + "",
      encrypt
    );

    return {
      encrypt,
      signature,
      timestamp,
      nonce,
    };
  }
  async decryptMsg(timestamp, nonce, encrypt) {
    const ac = new AesCrypt(this.encodingAesKey);
    const decrypt = await ac.decrypt(encrypt, this.appId);
    return decrypt;
  }
}
