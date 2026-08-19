/*!
 * activation.js —— 通用离线激活网关（纯前端，无服务器/无 Electron 依赖）
 * ------------------------------------------------------------------
 * 用法：在游戏 index.html 的 <head> 里加一行即可，不需要改游戏本体代码：
 *   <script src="./activation.js"></script>
 *
 * 原理：
 *   1. 脚本一加载就立刻在 <html> 下插入一个铺满全屏的 Shadow DOM 遮罩层，
 *      挡住整个页面（不依赖 document.body，因为此时 body 可能还没解析）。
 *   2. 用浏览器本地随机数生成一个"机器码"（因为纯网页拿不到真实硬件 ID），
 *      首次生成后永久存在 localStorage 里，以后每次打开都一样。
 *   3. 验证逻辑与激活码格式，和原来 dev_tool.py / ed25519_pure.py 完全一致：
 *        - 消息 = clean_code(machineCode) 的 UTF-8 编码
 *        - 签名 = Ed25519(message, 私钥)，64 字节
 *        - 激活码 = base32(signature) 去掉 '=' 补齐符，每 4 位一组用 '-' 连接
 *      开发者依然用同一套 dev_tool.py 给玩家签发激活码，完全兼容，不用换算法。
 *   4. 验证通过后把 {机器码, 激活码} 存进 localStorage，并移除遮罩层，
 *      游戏本身的脚本/画面这时候才会显现出来（游戏脚本其实一直在后台正常
 *      加载/执行，只是被遮罩挡住看不见——纯前端环境下没法真正暂停游戏本体，
 *      这是唯一做不到"完全跳过加载"的地方）。之后再次打开页面会先显示遮罩、
 *      在后台重新校验一次签名（通常几十毫秒内完成），通过后自动移除遮罩，
 *      不需要重新输入激活码。
 *
 * 复用到其他网页游戏：
 *   把下面 CONFIG.PUBLIC_KEY_HEX 换成对应游戏的公钥（对应各自的 private_key.txt
 *   签发的激活码）即可，其余代码不用动。不同游戏只要 PUBLIC_KEY_HEX 不同，
 *   localStorage 的存储 key 会自动按当前页面路径区分，不会互相冲突。
 * ------------------------------------------------------------------
 */
(function () {
  'use strict';

  // 防止脚本被重复引入
  if (window.__ACTIVATION_JS_LOADED__) return;
  window.__ACTIVATION_JS_LOADED__ = true;

  // ============================================================
  // CONFIG —— 换到别的游戏时，一般只需要改这一块
  // ============================================================
  var CONFIG = {
    // 对应 dev_tool.py genkeys 生成的 public_key.txt 内容（64 位 hex）
    PUBLIC_KEY_HEX:
      'a9c4e58bd4b466b0cb0c9b0ed06e0503e9f0a8d6037a3cfe5124b240542ea9fb',
    TITLE: '需要激活',
    SUBTITLE: '请将下方机器码提供给开发者以获取激活码',
    MACHINE_CODE_LABEL: '本机机器码',
    ACTIVATION_CODE_LABEL: '激活码',
    ACTIVATION_CODE_PLACEHOLDER: '请输入开发者发给你的激活码',
    SUBMIT_TEXT: '激活',
    COPY_TEXT: '复制',
    COPY_DONE_TEXT: '已复制',
    CHECKING_TEXT: '正在校验激活状态...',
  };

  // ============================================================
  // 0. 小工具
  // ============================================================
  function simpleHash(str) {
    // djb2，只是用来给同一域名下不同游戏的 localStorage 做区分，不涉及安全
    var h = 5381;
    for (var i = 0; i < str.length; i++) {
      h = ((h << 5) + h + str.charCodeAt(i)) >>> 0;
    }
    return h.toString(36);
  }

  var STORAGE_NS = 'activation_' + simpleHash(location.pathname || '/') + '_';
  var STORAGE_KEY_MACHINE = STORAGE_NS + 'machine_code';
  var STORAGE_KEY_RECORD = STORAGE_NS + 'record';

  function hexToBytes(hex) {
    var bytes = new Uint8Array(hex.length / 2);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  function concatBytes() {
    var total = 0;
    for (var i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total);
    var offset = 0;
    for (var j = 0; j < arguments.length; j++) {
      out.set(arguments[j], offset);
      offset += arguments[j].length;
    }
    return out;
  }

  // 与 Python 端 clean_code 完全一致：去掉横杠/空格，去首尾空白，转大写
  function cleanCode(code) {
    return String(code).replace(/-/g, '').replace(/\s/g, '').trim().toUpperCase();
  }

  // ---- Base32 (RFC 4648，无填充，大写) —— 对应 python base64.b32encode(...).rstrip('=') ----
  var B32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function base32Encode(bytes) {
    var bits = '';
    for (var i = 0; i < bytes.length; i++) {
      bits += bytes[i].toString(2).padStart(8, '0');
    }
    var out = '';
    for (var j = 0; j < bits.length; j += 5) {
      var chunk = bits.substr(j, 5);
      if (chunk.length < 5) chunk = chunk.padEnd(5, '0');
      out += B32_ALPHABET[parseInt(chunk, 2)];
    }
    return out;
  }

  function base32Decode(str) {
    str = String(str).toUpperCase().replace(/=+$/, '');
    var bits = '';
    for (var i = 0; i < str.length; i++) {
      var val = B32_ALPHABET.indexOf(str[i]);
      if (val === -1) throw new Error('激活码包含非法字符');
      bits += val.toString(2).padStart(5, '0');
    }
    var bytes = [];
    for (var j = 0; j + 8 <= bits.length; j += 8) {
      bytes.push(parseInt(bits.substr(j, 8), 2));
    }
    return new Uint8Array(bytes);
  }

  function groupWithDash(str, groupSize) {
    var parts = [];
    for (var i = 0; i < str.length; i += groupSize) {
      parts.push(str.slice(i, i + groupSize));
    }
    return parts.join('-');
  }

  // ============================================================
  // 1. 纯 JS 移植的 Ed25519 验证（对应 ed25519_pure.py，同一套经典参考实现）
  //    只需要"验证"，不需要签名/生成密钥，所以只搬运 checkvalid 相关部分
  // ============================================================
  var ed25519 = (function () {
    var q = (1n << 255n) - 19n;
    var l = (1n << 252n) + 27742317777372353535851937790883648493n;

    function mod(a, m) {
      var r = a % m;
      return r >= 0n ? r : r + m;
    }

    function expmod(base, e, m) {
      if (e === 0n) return 1n;
      var t = expmod(base, e / 2n, m);
      t = mod(t * t, m);
      if (e & 1n) t = mod(t * base, m);
      return t;
    }

    function inv(x) {
      return expmod(x, q - 2n, q);
    }

    var d = mod(-121665n * inv(121666n), q);
    var I = expmod(2n, (q - 1n) / 4n, q);

    function xrecover(y) {
      var xx = mod((y * y - 1n) * inv(d * y * y + 1n), q);
      var x = expmod(xx, (q + 3n) / 8n, q);
      if (mod(x * x - xx, q) !== 0n) x = mod(x * I, q);
      if (mod(x, 2n) !== 0n) x = q - x;
      return x;
    }

    var By = mod(4n * inv(5n), q);
    var Bx = xrecover(By);
    var B = [mod(Bx, q), mod(By, q)];

    function edwards(P, Q) {
      var x1 = P[0], y1 = P[1], x2 = Q[0], y2 = Q[1];
      var x3 = mod((x1 * y2 + x2 * y1) * inv(1n + d * x1 * x2 * y1 * y2), q);
      var y3 = mod((y1 * y2 + x1 * x2) * inv(1n - d * x1 * x2 * y1 * y2), q);
      return [x3, y3];
    }

    function scalarmult(P, e) {
      if (e === 0n) return [0n, 1n];
      var Q = scalarmult(P, e / 2n);
      Q = edwards(Q, Q);
      if (e & 1n) Q = edwards(Q, P);
      return Q;
    }

    function bytesFromBitFn(bitAt) {
      var bytes = new Uint8Array(32);
      for (var i = 0; i < 32; i++) {
        var byte = 0;
        for (var j = 0; j < 8; j++) {
          if (bitAt(i * 8 + j)) byte |= (1 << j);
        }
        bytes[i] = byte;
      }
      return bytes;
    }

    function encodeint(y) {
      return bytesFromBitFn(function (idx) {
        return ((y >> BigInt(idx)) & 1n) === 1n;
      });
    }

    function encodepoint(P) {
      var x = P[0], y = P[1];
      return bytesFromBitFn(function (idx) {
        if (idx < 255) return ((y >> BigInt(idx)) & 1n) === 1n;
        return (x & 1n) === 1n;
      });
    }

    function bitOf(bytes, i) {
      return (bytes[(i / 8) | 0] >> (i % 8)) & 1;
    }

    function isoncurve(P) {
      var x = P[0], y = P[1];
      return mod(-x * x + y * y - 1n - d * x * x * y * y, q) === 0n;
    }

    function decodeint(s) {
      var y = 0n;
      for (var i = 0; i < 256; i++) {
        if (bitOf(s, i)) y |= (1n << BigInt(i));
      }
      return y;
    }

    function decodepoint(s) {
      var y = 0n;
      for (var i = 0; i < 255; i++) {
        if (bitOf(s, i)) y |= (1n << BigInt(i));
      }
      var x = xrecover(y);
      if ((x & 1n) !== BigInt(bitOf(s, 255))) x = q - x;
      var P = [x, y];
      if (!isoncurve(P)) throw new Error('signature point not on curve');
      return P;
    }

    async function sha512(bytes) {
      var digest = await crypto.subtle.digest('SHA-512', bytes);
      return new Uint8Array(digest);
    }

    async function Hint(m) {
      var h = await sha512(m);
      var sum = 0n;
      for (var i = 0; i < 512; i++) {
        if (bitOf(h, i)) sum |= (1n << BigInt(i));
      }
      return sum;
    }

    // 对应 ed25519_pure.py 的 checkvalid(s, m, pk)
    async function checkvalid(s, m, pk) {
      if (s.length !== 64) throw new Error('signature length is wrong');
      if (pk.length !== 32) throw new Error('public-key length is wrong');
      var R = decodepoint(s.slice(0, 32));
      var A = decodepoint(pk);
      var S = decodeint(s.slice(32, 64));
      var h = await Hint(concatBytes(encodepoint(R), pk, m));
      var left = scalarmult(B, S);
      var right = edwards(R, scalarmult(A, h));
      if (left[0] !== right[0] || left[1] !== right[1]) {
        throw new Error('signature does not pass verification');
      }
      return true;
    }

    return { checkvalid: checkvalid };
  })();

  // ============================================================
  // 2. 机器码：网页环境拿不到真实硬件 ID，改用"首次随机生成 + 本地持久化"，
  //    格式沿用 XXXX-XXXX-XXXX-XXXX 风格，clean_code 之后再签名/验证
  // ============================================================
  function getOrCreateMachineCode() {
    try {
      var saved = localStorage.getItem(STORAGE_KEY_MACHINE);
      if (saved) return saved;
    } catch (e) {
      /* localStorage 不可用时忽略，走内存内的临时机器码 */
    }
    var raw = new Uint8Array(10);
    crypto.getRandomValues(raw);
    var code = groupWithDash(base32Encode(raw), 4);
    try {
      localStorage.setItem(STORAGE_KEY_MACHINE, code);
    } catch (e) {
      /* 忽略 */
    }
    return code;
  }

  function loadRecord() {
    try {
      var raw = localStorage.getItem(STORAGE_KEY_RECORD);
      return raw ? JSON.parse(raw) : null;
    } catch (e) {
      return null;
    }
  }

  function saveRecord(record) {
    try {
      localStorage.setItem(STORAGE_KEY_RECORD, JSON.stringify(record));
    } catch (e) {
      /* 忽略：存不下就只在本次会话内生效 */
    }
  }

  async function verifyActivationCode(machineCode, activationCode) {
    var pk = hexToBytes(CONFIG.PUBLIC_KEY_HEX);
    var message = new TextEncoder().encode(cleanCode(machineCode));
    var sig = base32Decode(cleanCode(activationCode));
    return ed25519.checkvalid(sig, message, pk);
  }

  // ============================================================
  // 3. 界面：Shadow DOM 全屏遮罩，尽早插入到 <html> 下（此时 body 可能还没解析）
  // ============================================================
  var host = document.createElement('div');
  host.id = '__activation_overlay_host__';
  var root = host.attachShadow({ mode: 'open' });

  root.innerHTML =
    '<style>' +
    '  :host { all: initial; }' +
    '  .mask {' +
    '    position: fixed; inset: 0; z-index: 2147483647;' +
    '    display: flex; align-items: center; justify-content: center;' +
    '    background: #1b1c22;' +
    '    font-family: "Microsoft YaHei", "PingFang SC", sans-serif;' +
    '    color: #eee;' +
    '  }' +
    '  * { box-sizing: border-box; }' +
    '  .card {' +
    '    width: 400px; max-width: 90vw; padding: 28px;' +
    '    background: #24252d; border-radius: 10px;' +
    '    box-shadow: 0 8px 24px rgba(0,0,0,0.4);' +
    '  }' +
    '  h1 { font-size: 18px; margin: 0 0 4px; }' +
    '  p.sub { margin: 0 0 20px; font-size: 13px; color: #999; }' +
    '  .checking { font-size: 13px; color: #999; text-align: center; }' +
    '  label { display: block; font-size: 12px; color: #aaa; margin-bottom: 6px; }' +
    '  .machine-code-box { display: flex; gap: 8px; margin-bottom: 20px; }' +
    '  .machine-code-box input {' +
    '    flex: 1; background: #17181d; border: 1px solid #3a3b45; color: #6fd0ff;' +
    '    padding: 10px; border-radius: 6px; font-family: monospace; font-size: 14px;' +
    '    letter-spacing: 1px; min-width: 0;' +
    '  }' +
    '  .machine-code-box button {' +
    '    padding: 0 14px; border: 1px solid #3a3b45; background: #2f3038; color: #ddd;' +
    '    border-radius: 6px; cursor: pointer; font-size: 12px;' +
    '  }' +
    '  .machine-code-box button:hover { background: #3a3b45; }' +
    '  textarea {' +
    '    width: 100%; height: 90px; background: #17181d; border: 1px solid #3a3b45;' +
    '    color: #eee; padding: 10px; border-radius: 6px; font-family: monospace;' +
    '    font-size: 13px; resize: none; margin-bottom: 14px;' +
    '  }' +
    '  .submit-btn {' +
    '    width: 100%; padding: 12px; background: #4c7cff; border: none; color: #fff;' +
    '    border-radius: 6px; font-size: 14px; cursor: pointer;' +
    '  }' +
    '  .submit-btn:hover { background: #3d69ea; }' +
    '  .submit-btn:disabled { background: #444; cursor: not-allowed; }' +
    '  .msg { margin-top: 12px; font-size: 13px; min-height: 18px; }' +
    '  .msg.error { color: #ff7373; }' +
    '  .msg.success { color: #63e08a; }' +
    '</style>' +
    '<div class="mask">' +
    '  <div class="card" id="card">' +
    '    <div class="checking" id="checking">' + CONFIG.CHECKING_TEXT + '</div>' +
    '  </div>' +
    '</div>';

  document.documentElement.appendChild(host);

  function renderForm(machineCode) {
    var card = root.getElementById('card');
    card.innerHTML =
      '<h1>' + CONFIG.TITLE + '</h1>' +
      '<p class="sub">' + CONFIG.SUBTITLE + '</p>' +
      '<label>' + CONFIG.MACHINE_CODE_LABEL + '</label>' +
      '<div class="machine-code-box">' +
      '  <input id="machineCode" readonly />' +
      '  <button id="copyBtn">' + CONFIG.COPY_TEXT + '</button>' +
      '</div>' +
      '<label>' + CONFIG.ACTIVATION_CODE_LABEL + '</label>' +
      '<textarea id="activationCode" placeholder="' + CONFIG.ACTIVATION_CODE_PLACEHOLDER + '"></textarea>' +
      '<button class="submit-btn" id="submitBtn">' + CONFIG.SUBMIT_TEXT + '</button>' +
      '<div class="msg" id="msg"></div>';

    var machineCodeInput = root.getElementById('machineCode');
    var activationCodeInput = root.getElementById('activationCode');
    var submitBtn = root.getElementById('submitBtn');
    var copyBtn = root.getElementById('copyBtn');
    var msgEl = root.getElementById('msg');

    machineCodeInput.value = machineCode;

    function setMsg(text, type) {
      msgEl.textContent = text;
      msgEl.className = 'msg' + (type ? ' ' + type : '');
    }

    copyBtn.addEventListener('click', function () {
      var done = function () {
        copyBtn.textContent = CONFIG.COPY_DONE_TEXT;
        setTimeout(function () {
          copyBtn.textContent = CONFIG.COPY_TEXT;
        }, 1500);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(machineCodeInput.value).then(done, function () {
          fallbackCopy();
        });
      } else {
        fallbackCopy();
      }
      function fallbackCopy() {
        machineCodeInput.removeAttribute('readonly');
        machineCodeInput.select();
        try {
          document.execCommand('copy');
          done();
        } catch (e) {
          setMsg('复制失败，请手动选中复制', 'error');
        }
        machineCodeInput.setAttribute('readonly', 'readonly');
      }
    });

    submitBtn.addEventListener('click', async function () {
      var code = activationCodeInput.value.trim();
      if (!code) {
        setMsg('请输入激活码', 'error');
        return;
      }

      submitBtn.disabled = true;
      setMsg('验证中...', '');

      try {
        var valid = await verifyActivationCode(machineCode, code);
        if (valid) {
          setMsg('激活成功，正在启动游戏...', 'success');
          saveRecord({ machineCode: machineCode, activationCode: code });
          setTimeout(removeOverlay, 400);
        } else {
          setMsg('激活失败，请检查激活码是否正确', 'error');
          submitBtn.disabled = false;
        }
      } catch (err) {
        setMsg('激活失败，请检查激活码是否正确', 'error');
        submitBtn.disabled = false;
      }
    });
  }

  function removeOverlay() {
    if (host.parentNode) host.parentNode.removeChild(host);
  }

  // ============================================================
  // 4. 启动流程
  // ============================================================
  (async function start() {
    var machineCode = getOrCreateMachineCode();
    var record = loadRecord();

    if (record && record.machineCode === machineCode && record.activationCode) {
      try {
        var ok = await verifyActivationCode(record.machineCode, record.activationCode);
        if (ok) {
          removeOverlay();
          return;
        }
      } catch (e) {
        /* 校验失败，继续走下面展示表单的流程 */
      }
    }

    renderForm(machineCode);
  })();
})();
