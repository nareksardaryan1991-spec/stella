/* Собирает index.html: берёт template.html и вшивает в него
   зашифрованный текст письма из content.json.

   Запуск: node build.mjs                                        */

import { readFile, writeFile } from "node:fs/promises";
import { webcrypto as crypto } from "node:crypto";

const ITERATIONS = 310000;
const b64 = bytes => Buffer.from(bytes).toString("base64");

const raw = JSON.parse(await readFile("content.json", "utf8"));
const login = raw._login;
const password = raw._password;

if (!login || !password) {
  throw new Error("В content.json нужны поля _login и _password");
}
if (password.length < 12) {
  console.warn("Внимание: пароль короче 12 символов. Шифртекст лежит в публичном "
    + "репозитории, а короткий пароль подбирается перебором.");
}

// всё, что начинается с подчёркивания, в письмо не попадает
const letter = Object.fromEntries(
  Object.entries(raw).filter(([k]) => !k.startsWith("_"))
);

const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));

const material = await crypto.subtle.importKey(
  "raw",
  new TextEncoder().encode(login.trim().toLowerCase() + "\u0000" + password),
  "PBKDF2", false, ["deriveKey"]
);
const key = await crypto.subtle.deriveKey(
  { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
  material,
  { name: "AES-GCM", length: 256 },
  false, ["encrypt", "decrypt"]
);

const plaintext = new TextEncoder().encode(JSON.stringify(letter));
const data = new Uint8Array(
  await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext)
);

// самопроверка: расшифровываем обратно тем же ключом
const back = JSON.parse(new TextDecoder().decode(
  await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data)
));
if (JSON.stringify(back) !== JSON.stringify(letter)) {
  throw new Error("Самопроверка не прошла: расшифрованное не совпало с исходным");
}

const vault = { salt: b64(salt), iv: b64(iv), iterations: ITERATIONS, data: b64(data) };

const template = await readFile("template.html", "utf8");
const out = template.replace(
  /\/\*VAULT\*\/[\s\S]*?\/\*VAULT\*\//,
  () => "/*VAULT*/ " + JSON.stringify(vault) + " /*VAULT*/"
);
if (out === template) {
  throw new Error("В template.html не найден маркер /*VAULT*/");
}

await writeFile("index.html", out);
console.log("index.html собран. Шифртекст: " + vault.data.length + " символов base64.");
