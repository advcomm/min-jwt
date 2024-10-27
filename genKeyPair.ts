import { generateKeyPairSync } from 'node:crypto';
import * as fs from 'node:fs';
const keysPath = '../process/keys/';

// Generate key pairs multiple times
for (let i = 0; i < 50; i++) {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const pemPrivateKey = privateKey.export({ format: 'pem', type: 'pkcs1' }).toString();
  const pemPublicKey = publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const fileName = keysPath + Buffer.from(pemPublicKey.substring(101, 109), 'base64').toString('hex').replace(/(.{4})/g, '$1-').slice(0, -1) + '.key';// Replace with your desired file name. Currently chooses characters 101 to 109 from the pem public key and puts them as hyphen separated hex values. Only stores private key as public key can be generated from the private key later.
  fs.writeFile(fileName, pemPrivateKey, (err) => {
		if (err) {
				console.error('Error writing to file:', err);
		} else {
				console.log(fileName, 'File written successfully\n');
		}
		});
}