const senv = require("../index");
const crypto = require("crypto");
const { writeFileSync, rmSync, existsSync } = require("fs");

const TMPDIR = "";

const EXAMPLE_ENV_FILE = `
# test comment
ENV_VAR=123

 # test comment 2
ENV_VAR_2=abc
`.trim();

test("encrypts/decrypts string successfully", () => {
    const testString = "Hello world!";
    const testPassword = "password";
    const iv = crypto.randomBytes(16);
    const encryptedString = senv.encryptString(testString, testPassword, iv);

    expect(encryptedString).not.toBe(testString);
    expect(encryptedString).not.toBeNull();

    expect(senv.decryptString(encryptedString, testPassword, iv)).toBe(
        testString
    );
});

test("gets individual .env file password from env var", () => {
    const password = "password";
    process.env.DOTENV_PROD_PASS = password;

    expect(senv.getPasswordFromEnvironment(".env.prod")).toBe(password);
    expect(senv.getPasswordFromEnvironment(".env.prod.enc")).toBe(password);
    expect(senv.getPasswordFromEnvironment(".env.prod.encrypted")).toBe(
        password
    );

    delete process.env.DOTENV_PROD_PASS;
});

test("gets individual .env file password from password file", () => {
    const password = "password";
    const path = ".env.prod.pass";
    writeFileSync(path, password);

    expect(senv.getPasswordFromEnvironment(".env.prod")).toBe(password);
    expect(senv.getPasswordFromEnvironment(".env.prod.enc")).toBe(password);
    expect(senv.getPasswordFromEnvironment(".env.prod.encrypted")).toBe(
        password
    );

    rmSync(path);
});

test("gets global .env file password from env var", () => {
    const password = "password";
    process.env.DOTENV_PASS = password;

    expect(senv.getPasswordFromEnvironment(".env.prod")).toBe(password);
    expect(senv.getPasswordFromEnvironment(".env.prod.enc")).toBe(password);
    expect(senv.getPasswordFromEnvironment(".env.prod.encrypted")).toBe(
        password
    );

    delete process.env.DOTENV_PASS;
});

test("gets global .env file password from password file", () => {
    const password = "password";
    const path = ".env.pass";
    writeFileSync(path, password);

    expect(senv.getPasswordFromEnvironment(".env.prod")).toBe(password);
    expect(senv.getPasswordFromEnvironment(".env.prod.enc")).toBe(password);
    expect(senv.getPasswordFromEnvironment(".env.prod.encrypted")).toBe(
        password
    );

    rmSync(path);
});

test("encrypting env file fails without password", () => {
    expect(() => senv.encryptEnvFile("path", undefined)).toThrow();
    expect(() => senv.encryptEnvFile("path", null)).toThrow(
        "No password provided."
    );
    expect(() => senv.encryptEnvFile("path", "")).toThrow("password");
});

test("decrypting env file fails without password", () => {
    expect(() => senv.decryptEnvFile("path", undefined)).toThrow("password");
    expect(() => senv.decryptEnvFile("path", null)).toThrow("password");
    expect(() => senv.decryptEnvFile("path", "")).toThrow("password");
});

test("encrypted env file is written successfully", () => {
    const path = `${TMPDIR}.env.test1`;
    const encryptedEnvPath = `${TMPDIR}.env.test1.enc`;

    writeFileSync(path, EXAMPLE_ENV_FILE);

    senv.encryptEnvFile(path, encryptedEnvPath, "password");

    expect(existsSync(encryptedEnvPath)).toBeTruthy();

    rmSync(path);
    rmSync(encryptedEnvPath);
});

test("encrypted env file is written successfully, when output path is not provided", () => {
    const path = `${TMPDIR}.env.test1`;
    const encryptedEnvPath = `${TMPDIR}.env.test1.enc`;

    writeFileSync(path, EXAMPLE_ENV_FILE);

    senv.encryptEnvFile(path, undefined, "password");

    expect(existsSync(encryptedEnvPath)).toBeTruthy();

    rmSync(path);
    rmSync(encryptedEnvPath);
});

test("encrypted env file has correct variables", () => {
    const path = `${TMPDIR}.env.test1`;
    writeFileSync(path, EXAMPLE_ENV_FILE);

    const encryptedEnvFile = senv.encryptEnvFile(path, null, "password", true);

    expect(encryptedEnvFile).toContain("ENV_VAR");
    expect(encryptedEnvFile).toContain("ENV_VAR_2");

    rmSync(path);
});

test("encrypted env file variable values have changed", () => {
    const path = `${TMPDIR}.env.test2`;
    writeFileSync(path, EXAMPLE_ENV_FILE);

    const encryptedEnvFile = senv.encryptEnvFile(path, null, "password", true);

    expect(encryptedEnvFile).not.toEqual(EXAMPLE_ENV_FILE);

    rmSync(path);
});

test("decrypted env file is written successfully", () => {
    const path = `${TMPDIR}.env.test1`;
    const encryptedEnvPath = `${TMPDIR}.env.test1.enc`;

    writeFileSync(path, EXAMPLE_ENV_FILE);

    senv.encryptEnvFile(path, encryptedEnvPath, "password");
    rmSync(path);

    senv.decryptEnvFile(encryptedEnvPath, path, "password");
    expect(existsSync(path)).toBeTruthy();

    rmSync(path);
    rmSync(encryptedEnvPath);
});

test("decrypted env file is written successfully, when output path is not provided", () => {
    const path = `${TMPDIR}.env.test1`;
    const encryptedEnvPath = `${TMPDIR}.env.test1.enc`;

    writeFileSync(path, EXAMPLE_ENV_FILE);

    senv.encryptEnvFile(path, encryptedEnvPath, "password");
    rmSync(path);

    senv.decryptEnvFile(encryptedEnvPath, undefined, "password");
    expect(existsSync(path)).toBeTruthy();

    rmSync(path);
    rmSync(encryptedEnvPath);
});

test("decrypted env file has correct variables", () => {
    const envVarPath = `${TMPDIR}.env.test3`;
    const encryptedEnvVarPath = `${TMPDIR}.env.test3.enc`;
    writeFileSync(envVarPath, EXAMPLE_ENV_FILE);

    senv.encryptEnvFile(envVarPath, encryptedEnvVarPath, "password");
    const decryptedEnvFile = senv.decryptEnvFile(
        encryptedEnvVarPath,
        null,
        "password",
        true
    );

    expect(decryptedEnvFile.trim()).toContain("ENV_VAR");
    expect(decryptedEnvFile.trim()).toContain("ENV_VAR_2");

    rmSync(envVarPath);
    rmSync(encryptedEnvVarPath);
});

test("decrypted env file variables are correct", () => {
    const envVarPath = `${TMPDIR}.env.test4`;
    const encryptedEnvVarPath = `${TMPDIR}.env.test4.enc`;
    writeFileSync(envVarPath, EXAMPLE_ENV_FILE);

    senv.encryptEnvFile(envVarPath, encryptedEnvVarPath, "password");
    const decryptedEnvFile = senv.decryptEnvFile(
        encryptedEnvVarPath,
        "",
        "password",
        true
    );

    expect(decryptedEnvFile.trim()).toEqual(EXAMPLE_ENV_FILE.trim());

    rmSync(envVarPath);
    rmSync(encryptedEnvVarPath);
});

test("decrypting env throws error when password is incorrect", () => {
    const envVarPath = `${TMPDIR}.env.test4`;
    const encryptedEnvVarPath = `${TMPDIR}.env.test4.enc`;
    writeFileSync(envVarPath, EXAMPLE_ENV_FILE);

    senv.encryptEnvFile(envVarPath, encryptedEnvVarPath, "password");
    expect(() =>
        senv.decryptEnvFile(encryptedEnvVarPath, null, "wrongpassword")
    ).toThrow("Incorrect password provided.");

    rmSync(envVarPath);
    rmSync(encryptedEnvVarPath);
});

test("decrypting env throws error when salt cannot be found", () => {
    const envVarPath = `${TMPDIR}.env.test4`;
    writeFileSync(envVarPath, EXAMPLE_ENV_FILE);

    expect(() => senv.decryptEnvFile(envVarPath, null, "password")).toThrow(
        "Could not find SENV_SALT in encrypted file."
    );

    rmSync(envVarPath);
});

test("decrypting env throws error when HMAC cannot be found", () => {
    const envVarPath = `${TMPDIR}.env.test4`;
    writeFileSync(envVarPath, EXAMPLE_ENV_FILE + "\nSENV_SALT=1234");

    expect(() => senv.decryptEnvFile(envVarPath, null, "password")).toThrow(
        "Could not find SENV_AUTHENTICATION in encrypted file."
    );

    rmSync(envVarPath);
});
