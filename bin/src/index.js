import { Command } from "commander";
import senv from "./senv";
import pkg from "../package.json";
const program = new Command();
program
    .version(pkg.version, "-v, --version")
    .description(pkg.description);
program.command("encrypt <filename>")
    .alias("e")
    .description("Encrypts a plain text .env file")
    .option("-o, --output [outfile]", "Output file")
    .option("-p, --password [password]", "Password to encrypt file with")
    .action((filename, options) => {
    try {
        const result = senv.encryptEnvFile(filename, options.output, options.password);
        console.log(result);
    }
    catch (err) {
        console.error(`${err}`);
        console.error(`See ${pkg.name} encrypt --help for details.`);
        process.exit(1);
    }
});
program.command("decrypt <filename>")
    .alias("d")
    .description("Decrypts an encrypted .env file")
    .option("-o, --output [outfile]", "Output File")
    .option("-p, --password [password]", "Password to decrypt file with")
    .action((filename, options) => {
    try {
        const result = senv.decryptEnvFile(filename, options.output, options.password);
        console.log(result);
    }
    catch (err) {
        console.error(`${err}`);
        console.error(`See ${pkg.name} decrypt --help for details.`);
        process.exit(1);
    }
});
// Display error message on invalid command
program.on("command:*", () => {
    console.error("Invalid command: %s\nSee --help for a list of available commands.", program.args.join(" "));
    process.exit(1);
});
program.parse(process.argv);
function printHelp() {
    program.outputHelp();
    console.log("");
    console.log("Run `senv [command] --help` for more details about a command");
    console.log("");
    console.log("Examples:");
    console.log("");
    console.log("  Encrypt a plain text .env file:");
    console.log(`  $ ${pkg.name} encrypt .env -o .env.enc`);
    console.log("");
    console.log("  Decrypt an encrypted .env file:");
    console.log(`  $ ${pkg.name} decrypt .env.enc -o .env`);
}
if (!process.argv.slice(2).length) {
    printHelp();
}
export function encryptString(testString, testPassword, iv) {
    throw new Error("Function not implemented.");
}
//# sourceMappingURL=index.js.map