import { createPublicKey, createVerify, KeyObject } from 'node:crypto';

export const verifyToken = (jwt: string): JSON | null => {
    let payload: JSON | null = null;
    if (!process.env.pemPublicKey) throw new Error('Public Key not found');
    try {
        const algos = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];
    	const j = jwt.split('.');
	    if (j.length !== 3) throw new Error('Invalid JWT. Should have exactly three segments');

	    const _header = Buffer.from(j[0], 'base64url').toString('utf8');
    	const header = JSON.parse(_header);
        if (header.typ !== 'JWT') throw new Error('Token typ is not JWT');
        const alg: string = header.alg;
        if (!alg) throw new Error('alg not found');
        if (!algos.includes(alg)) throw new Error('alg not supported');
		const key: KeyObject = createPublicKey(process.env.pemPublicKey);
        const signature = Buffer.from(j[2], 'base64url');
        const strength = alg.slice(2);
        if (['256', '384', '512'].includes(strength)) {
            const hash = 'SHA' + strength;
            const verify = createVerify(hash).update(j[0]).update('.').update(j[1]).end();
            if (verify.verify(key, signature)) {
                payload = JSON.parse(Buffer.from(j[1], 'base64url').toString('utf8'));
            }
        } else throw new Error('Encryption strength not supported');
    } catch (error) {
        throw new Error('Header in JWT could not be parsed as valid json');
    }
    return payload;
}
