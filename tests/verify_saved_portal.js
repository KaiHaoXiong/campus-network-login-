// Offline oracle: evaluate only the inspected MD5 module and pure encode(info, token)
// function from the user's saved school page. No DOM, credentials, AJAX or login code.
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const {spawnSync} = require("child_process");
const crypto = require("crypto");
const directory = process.argv[2] || path.join(__dirname, "../.runtime/portal-page_files");
const files = fs.readdirSync(directory);
const read = name => fs.readFileSync(path.join(directory, files.find(file => file.startsWith(name))), "utf8").replace(/\r\n/g, "\n");
const library = read("all.min.js");
const md5Source = library.slice(library.indexOf("//md5"), library.indexOf("//js-sha1"));
if (!md5Source || md5Source.length > 10000) throw new Error("Unexpected MD5 source layout");
const portal = read("Portal.js");
const start = portal.indexOf("function value(info, token)");
const boundary = portal.indexOf("\n    _getToken.set", start);
const end = portal.lastIndexOf("\n      }", boundary) + "\n      }".length;
if (start < 0 || boundary < 0 || end <= start || end - start > 10000) throw new Error("Unexpected encode source layout");
const context = vm.createContext({module: {exports: {}},
    _this: {clone: value => ({...value})},
    $: {base64: {alphabet: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        setAlpha(value) { this.alphabet = value; },
        encode(value) {
            const standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            return Buffer.from(value, "latin1").toString("base64").replace(/[A-Za-z0-9+/]/g,
                char => this.alphabet[standard.indexOf(char)]);
        }}},
}, {codeGeneration: {strings: false, wasm: false}});
vm.runInContext(md5Source, context, {timeout: 500});
vm.runInContext("encodeInfo = (" + portal.slice(start, end) + ")", context, {timeout: 500});
const cases = ["4", "8"].flatMap(ac_id => ["test123", "密码😀"].map(password => ({
    info: {username: "demo@cmcc", password, ip: "192.0.2.23", acid: ac_id, enc_ver: "srun_bx1"},
    token: "0123456789abcdef0123456789abcdef",
})));
const expected = cases.map(sample => {
    context.sample = sample;
    const hmd5 = vm.runInContext("module.exports(sample.info.password, sample.token)", context, {timeout: 500});
    const encrypted_info = vm.runInContext("encodeInfo(sample.info, sample.token)", context, {timeout: 500});
    const parts = [sample.info.username, hmd5, sample.info.acid, sample.info.ip, "200", "1", encrypted_info];
    const chksum = crypto.createHash("sha1").update(parts.map(value => sample.token + value).join("")).digest("hex");
    return {hmd5, encrypted_info, chksum};
});
const python = `import json,sys
from srun_encrypt import get_md5, make_encrypted_info, make_checksum
out=[]
for c in json.load(sys.stdin):
 i=c['info']; t=c['token']; h=get_md5(i['password'],t)
 e=make_encrypted_info(i['username'],i['password'],i['ip'],i['acid'],i['enc_ver'],t)
 out.append(dict(hmd5=h,encrypted_info=e,chksum=make_checksum(t,i['username'],h,i['acid'],i['ip'],'200','1',e)))
print(json.dumps(out))`;
const result = spawnSync(process.env.PYTHON || "python", ["-B", "-c", python], {
    cwd: path.join(__dirname, ".."), input: JSON.stringify(cases), encoding: "utf8",
    env: {...process.env, PYTHONUTF8: "1"},
});
if (result.error || result.status !== 0) throw new Error(result.error || result.stderr);
const actual = JSON.parse(result.stdout);
let failures = 0;
expected.forEach((value, index) => {
    const differences = Object.keys(value).filter(field => value[field] !== actual[index][field]);
    console.log(`School source case ${index + 1}: ${differences.length ? "FAIL " + differences.join(", ") : "PASS"}`);
    if (differences.length) failures++;
});
process.exitCode = failures ? 1 : 0;
