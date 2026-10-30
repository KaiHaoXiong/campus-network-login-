// Synthetic values only. Never place real passwords or challenge tokens here.
const {calculate, words} = require("./test_compare.js");
const info = {username: "demo@cmcc", password: "test123", ip: "10.246.6.57", acid: "8", enc_ver: "srun_bx1"};
const token = "test_challenge_12345";
console.log("Input word count:", words(JSON.stringify(info), true).length);
for (const mode of ["legacy", "portal_js"]) {
    console.log(mode, calculate({info, token, mode}));
}
