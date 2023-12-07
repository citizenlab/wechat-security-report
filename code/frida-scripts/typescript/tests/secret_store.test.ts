import { SecretStore, HkdfCall, EcdhCall, NamedKey } from '../src/secret_store';

function makeTestBuffer(values: number[]): ArrayBuffer {
    const buf = new ArrayBuffer(values.length);
    const bytes = new Uint8Array(buf);
    values.forEach((v, i) => bytes[i] = v);
    return buf;
}

describe('SecretStore', () => {
    test('works', () => {
        const store = new SecretStore();

        const PUB = makeTestBuffer([1]);
        const PRV = makeTestBuffer([2]);
        const KEY = makeTestBuffer([3]);

        const WRITE_KEY = Array(16).fill(1);
        const READ_KEY = Array(16).fill(2);
        const WRITE_IV = Array(8).fill(3);
        const READ_IV = Array(8).fill(4);
        const HKDF_RESULT = makeTestBuffer(WRITE_KEY.concat(READ_KEY).concat(WRITE_IV).concat(READ_IV));

        store.add(new NamedKey(PUB, `server_pub`));
        store.add(new NamedKey(PRV, `client_prv`));

        const ecdh = new EcdhCall(PUB, PRV)
        ecdh.result = KEY;
        store.add(ecdh);

        const handshake = new HkdfCall(56, 'whatever expansion', KEY);
        handshake.result = HKDF_RESULT;
        store.add(handshake);

        expect(store.findMatch(KEY)?.toString())
            .toBe(`server_pub0 = 0x01
client_prv0 = 0x02
ecdh0 = SHA256(ECDH_compute_key(client_prv0, client_prv0))`);

        expect(store.findMatch(makeTestBuffer(WRITE_KEY))?.toString())
            .toBe(`server_pub0 = 0x01
client_prv0 = 0x02
ecdh0 = SHA256(ECDH_compute_key(client_prv0, client_prv0))
hkdf_whatever_expansion0 = HKDF(ecdh0, "whatever expansion", 56).write_key`);
    })
})
