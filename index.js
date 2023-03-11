const crypto = require("crypto");
const { writeFileSync, readFileSync, existsSync } = require("fs");

const ENCRYPTION_ALGORITHM = "aes-256-ctr";
const HMAC_ALGORITHM = "sha256";
const AUTHENTICATION_KEY = "SENV_AUTHENTICATION";
const AUTHENTICATION_SALT = "SENV_SALT";

const PBKDF2_ITERATION_COUNT_FILE = 100000;
const PBKDF2_ITERATION_COUNT_STRING = 50000;

/**
 * Parse an env file into an array of lines.
 * @param {string} str - The string to be parsed.
 * @param {string} EOL - The line break character of the string.
 */
function parseEnv(str, EOL) {
    const parsedLines = [];
    const lines = str.toString().split(EOL);
    for (const line of lines) {
        const match = line.match(/^([^=:#]+?)[=:](.*)/);
        let key = line;
        let value = undefined;
        if (match) {
            key = match[1].trim();
            value = match[2].trim().replace(/['"]+/g, "");
        }
        parsedLines.push(typeof value === "undefined" ? [key] : [key, value]);
    }
    return parsedLines;
}

/**
 * Stringify an array of lines into an env file string.
 * @param {Array} lines - The array of lines to be stringified.
 * @param {string} EOL - The line break character of the string.
 */
function stringifyEnv(lines, EOL) {
    let result = "";
    lines.forEach(([key, value], idx) => {
        const line =
            typeof value === "undefined" ? key : `${key}=${String(value)}`;
        result += line + (idx !== lines.length -1 ? EOL : "");
    });
    return result;
}

/**
 * Get the line break character of a string
 * @param string
 */
function getLineBreakChar(string) {
    const indexOfLF = string.indexOf('\n', 1);
    if (indexOfLF === -1) {
        if (string.indexOf('\r') !== -1) return '\r'
        return '\n'
    }
    if (string[indexOfLF - 1] === '\r') return '\r\n'
    return '\n'
}

/**
 * Encrypts a string.
 * @param {string} string - The string to be encrypted.
 * @param {Buffer | string} key - The password with which to encrypt the string.
 * @param {Buffer} iv - The IV with which to encrypt the string.
 * @param {string=} name - the name of the variable
 */
function encryptString(string, key, iv, name = "") {
    if (typeof key === "string") {
        key = crypto.pbkdf2Sync(
            key,
            iv,
            PBKDF2_ITERATION_COUNT_STRING,
            32,
            "sha512"
        );
    }

    if (name) {
        iv = Buffer.from(createHmac(iv.toString(), name).slice(0, 32), "hex");
    }

    const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
    let encrypted = cipher.update(string, "utf8", "hex");
    encrypted += cipher.final("hex");

    return encrypted;
}

/**
 * Decrypts a string.
 * @param {string} string - The string to be decrypted.
 * @param {Buffer | string} key - The password with which to decrypt the string.
 * @param {Buffer} iv - The IV with which to encrypt the string.
 * @param {string=} name - the name of the variable
 */
function decryptString(string, key, iv, name = "") {
    if (typeof key === "string") {
        key = crypto.pbkdf2Sync(
            key,
            iv,
            PBKDF2_ITERATION_COUNT_STRING,
            32,
            "sha512"
        );
    }

    if (name) {
        iv = Buffer.from(createHmac(iv.toString(), name).slice(0, 32), "hex");
    }

    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
    let decrypted = decipher.update(string, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
}

/**
 * Creates an HMAC from a string and password.
 * @param {string} string - The string with which to create the HMAC.
 * @param {string} password - The password with which to create the HMAC.
 *
 * @returns {string}  - The created HMAC.
 */
function createHmac(string, password) {
    const hmac = crypto.createHmac(HMAC_ALGORITHM, password);
    hmac.update(string);
    return hmac.digest("hex");
}

/**
 * Gets a password for decryption from various sources in order.
 * @param {string} fileName - The file name to convert
 * @returns {string}  - the corresponding password file name
 */
function getPasswordFromEnvironment(fileName) {
    // Get password for individual .env file from environment variable
    const individualPasswordEnvVarName = fileName
        .replace(".encrypted", "") // ignore encrypted filename part
        .replace(".enc", "") // ignore encrypted filename part
        .replace(".", "DOT") // replace first . with DOT
        .replace(/\./g, "_") // replace all other . with _
        .concat("_PASS")
        .toUpperCase();

    if (process.env[individualPasswordEnvVarName]) {
        return process.env[individualPasswordEnvVarName];
    }

    // Get password for individual .env file from password file
    const individualPasswordFileName = fileName
        .replace(".encrypted", "") // ignore encrypted filename part
        .replace(".enc", "") // ignore encrypted filename part
        .concat(".pass");

    if (existsSync(individualPasswordFileName)) {
        return readFileSync(individualPasswordFileName, "utf8");
    }

    // Get password for all .env files from environment variable
    const globalPasswordEnvVarName = "DOTENV_PASS";

    if (process.env[globalPasswordEnvVarName]) {
        return process.env[globalPasswordEnvVarName];
    }

    // Get password for all .env files from file
    const globalPasswordFileName = ".env.pass";

    if (existsSync(globalPasswordFileName)) {
        return readFileSync(globalPasswordFileName, "utf8");
    }

    // if no password found, throw error
    throw new Error("No password provided.");
}

/**
 * Encrypts a .env file and writes it to disk.
 * @param {string} inputFile    - File path to plain text .env file to encrypt.
 * @param {string} outputFile   - File path to write encrypted .env file to.
 * @param {string} password     - The password with which to encrypt the .env file.
 *
 * @return {string}            - If outputFile is undefined, encrypted .env contents will be
 *                               returned as a string. Otherwise returns success message.
 */
function encryptEnvFile(inputFile, outputFile, password) {
    if (!password) {
        password = getPasswordFromEnvironment(inputFile);
    }

    const inputStr = readFileSync(inputFile, "utf8");
    const EOL = getLineBreakChar(inputStr);
    const envLines = parseEnv(inputStr, EOL);

    const salt = crypto.randomBytes(16).toString("hex");
    const key = crypto.pbkdf2Sync(
        password,
        salt,
        PBKDF2_ITERATION_COUNT_FILE,
        32,
        "sha512"
    );

    const hmac = createHmac(JSON.stringify(envLines), key.toString());

    // 32 because hex. (16 bytes)
    const iv = Buffer.from(hmac.slice(0, 32), "hex");

    const encryptedEnvLines = [];
    for (const [variableName, value] of envLines) {
        if (typeof value !== "undefined") {
            encryptedEnvLines.push([
                variableName,
                encryptString(value, key, iv, variableName),
            ]);
        } else {
            encryptedEnvLines.push([variableName]);
        }
    }

    encryptedEnvLines.push([AUTHENTICATION_KEY, hmac]);
    encryptedEnvLines.push([AUTHENTICATION_SALT, salt]);

    const encryptedEnvVariables = stringifyEnv(encryptedEnvLines, EOL);

    if (outputFile) {
        writeFileSync(outputFile, encryptedEnvVariables);
        return `Encrypted file successfully written to ${outputFile}`;
    } else {
        return encryptedEnvVariables;
    }
}

/**
 * Decrypts a .env file and writes it to disk.
 * @param {string} inputFile    - Path to encrypted .env file to decrypt.
 * @param {string} outputFile   - Path to write decrypted .env file to.
 * @param {string} password     - The password with which to decrypt the .env file.
 *
 * @return {string}            - If outputFile is undefined, encrypted .env contents will be
 *                               returned as a string. Otherwise returns success message.
 */
function decryptEnvFile(inputFile, outputFile, password) {
    if (!password) {
        password = getPasswordFromEnvironment(inputFile);
    }

    const inputStr = readFileSync(inputFile, "utf8");
    const EOL = getLineBreakChar(inputStr);
    const envLines = parseEnv(inputStr, EOL);
    const saltLine = envLines.find((line) => line[0] === AUTHENTICATION_SALT);
    if (!saltLine || !saltLine[1]) {
        throw new Error(`Could not find ${AUTHENTICATION_SALT} in encrypted file.`);
    }
    const salt = saltLine[1];
    const key = crypto.pbkdf2Sync(
        password,
        salt,
        PBKDF2_ITERATION_COUNT_FILE,
        32,
        "sha512"
    );

    const hmacLine = envLines.find((line) => line[0] === AUTHENTICATION_KEY);
    if (!hmacLine || !hmacLine[1]) {
        throw new Error(`Could not find ${AUTHENTICATION_KEY} in encrypted file.`);
    }
    const hmac = hmacLine[1];
    // 32 because hex. (16 bytes)
    const iv = Buffer.from(hmac.slice(0, 32), "hex");

    const decryptedEnvLines = [];
    for (const [variableName, value] of envLines) {
        if(variableName === AUTHENTICATION_SALT || variableName === AUTHENTICATION_KEY) {
            continue;
        }
        if(typeof value !== "undefined") {
            decryptedEnvLines.push([
                variableName,
                decryptString(value, key, iv, variableName),
            ]);
        } else {
            decryptedEnvLines.push([variableName]);
        }
    }

    const calculatedHmac = createHmac(JSON.stringify(decryptedEnvLines), key.toString());
    if (hmac !== calculatedHmac) {
        throw new Error("Incorrect password provided.");
    }

    const decryptedEnvVariables = stringifyEnv(decryptedEnvLines, EOL);

    if (outputFile) {
        writeFileSync(outputFile, decryptedEnvVariables);
        return `Decrypted file successfully written to ${outputFile}`;
    } else {
        return decryptedEnvVariables;
    }
}

module.exports = {
    encryptEnvFile,
    decryptEnvFile,
    encryptString,
    decryptString,
    getPasswordFromEnvironment,
};
