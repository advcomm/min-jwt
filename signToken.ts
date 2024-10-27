import { createPrivateKey, createSign, KeyObject, createSecretKey} from 'node:crypto';

export const signToken = function(alg: string, payload: JSON): string {
	const algs = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];
	if (!algs.includes(alg)) throw new Error('Algorithm not supported');
    if (!process.env.pemPrivateKey) throw new Error('Public Key not found');
	try {
        const secret = createPrivateKey(process.env.pemPrivateKey);
    	if (!secret) throw new Error('Could not find private key');
		const _header = Buffer.from('{"alg": "' + alg + '", "typ": "JWT"}').toString('base64url');
		const _payload = Buffer.from(JSON.stringify(payload)).toString('base64url');
		const sign = createSign('SHA256').update(_header).update('.').update(_payload).end();
		const signature = (sign.sign(secret)).toString('base64url');
		const jwt = _header + '.' + _payload + '.' + signature;
		return jwt;				
	} catch (error) {
		console.error(error);
		throw new Error('Could not sign token');
	}
}

