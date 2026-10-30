/** Independent JS reference. Both arithmetic groupings are explicit.
 * legacy: the existing Python implementation which has logged in successfully.
 * portal_js: the grouping in the originally checked-in JS reference.
 * Run: node test_compare.js (compares both modes with Python, offline).
 */
const crypto = require("crypto");
const ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";
const STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

function words(text, length) {
    const result = [];
    for (let i = 0; i < text.length; i += 4) {
        result.push((text.charCodeAt(i) | (text.charCodeAt(i + 1) || 0) << 8 |
            (text.charCodeAt(i + 2) || 0) << 16 | (text.charCodeAt(i + 3) || 0) << 24) >>> 0);
    }
    if (length) result.push(text.length);
    return result;
}

function encode(text, key, mode = "legacy") {
    if (!["legacy", "portal_js"].includes(mode)) throw new Error("Invalid encryption mode");
    if (text === "") return "";
    const v = words(text, true), k = words(key, false);
    while (k.length < 4) k.push(0);
    const n = v.length - 1;
    let z = v[n], sum = 0;
    for (let round = Math.floor(6 + 52 / (n + 1)); round > 0; round--) {
        sum = (sum + 0x9E3779B9) >>> 0;
        const e = (sum >>> 2) & 3;
        for (let p = 0; p <= n; p++) {
            const y = v[p === n ? 0 : p + 1];
            let m = (z >>> 5) ^ (y << 2);
            const b = (y >>> 3) ^ (z << 4);
            if (mode === "legacy") m += b ^ (sum ^ y);
            else m = ((m + b) | 0) ^ (sum ^ y);
            m += k[(p & 3) ^ e] ^ z;
            z = v[p] = (v[p] + m) >>> 0;
        }
    }
    const output = Buffer.alloc(v.length * 4);
    v.forEach((word, index) => output.writeUInt32LE(word, index * 4));
    return output.toString("base64").replace(/[A-Za-z0-9+/]/g,
        char => ALPHABET[STANDARD.indexOf(char)]);
}

function calculate(sample) {
    const {info, token, mode = "legacy"} = sample;
    let text = JSON.stringify(info);
    const encrypted_info = "{SRBX1}" + encode(text, token, mode);
    const hmd5 = crypto.createHmac("md5", token).update(info.password).digest("hex");
    const parts = [info.username, hmd5, info.acid, info.ip, "200", "1", encrypted_info];
    const chksum = crypto.createHash("sha1").update(parts.map(value => token + value).join("")).digest("hex");
    return {encrypted_info, hmd5, chksum};
}

function samples() {
    return ["legacy", "portal_js"].flatMap(mode => [
        {info: {username: "demo@cmcc", password: "test123", ip: "10.246.6.57", acid: "8", enc_ver: "srun_bx1"}, token: "test_challenge_12345", mode},
        {info: {username: "学生@cmcc", password: "密码😀", ip: "10.246.7.22", acid: "8", enc_ver: "srun_bx1"}, token: "0123456789abcdef0123456789abcdef", mode},
    ]);
}

module.exports = {calculate, encode, words};
if (require.main === module) {
    const assert = require("assert");
    const {spawnSync} = require("child_process");
    const cases = samples();
    const source = `import sys,json
from srun_encrypt import make_encrypted_info,get_md5,make_checksum
out=[]
for case in json.load(sys.stdin):
 i=case['info']; t=case['token']; h=get_md5(i['password'],t)
 e=make_encrypted_info(i['username'],i['password'],i['ip'],i['acid'],i['enc_ver'],t,mode=case['mode'])
 out.append(dict(encrypted_info=e,hmd5=h,chksum=make_checksum(t,i['username'],h,i['acid'],i['ip'],'200','1',e)))
print(json.dumps(out))`;
    const result = spawnSync(process.env.PYTHON || "python", ["-B", "-c", source],
        {cwd: __dirname, input: JSON.stringify(cases), encoding: "utf8", env: {...process.env, PYTHONUTF8: "1"}});
    if (result.error || result.status !== 0) {
        console.error("Python comparison failed:", result.error || result.stderr);
        process.exit(1);
    }
    assert.deepStrictEqual(cases.map(calculate), JSON.parse(result.stdout));
    console.log(`PASS: ${cases.length} Python/JS cases match (legacy + portal_js, ASCII + Unicode).`);
}
