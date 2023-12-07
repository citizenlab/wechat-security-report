interface Secret {
    isMatch(buf: ArrayBuffer, store: SecretStore): MatchResult | null;
    name: string;
}

class MatchResult {
    public sources: [string, string][];

    constructor(name: string, result: string) {
        this.sources = [[name, result]];
    }

    public toString() {
        return this.sources.map(([name, result]) => `${name} = ${result}`)
            .join('\n');
    }

    public push(name: string, result: string) {
        this.sources.push([name, result]);
    }

    public append(other: MatchResult) {
        other.sources.forEach(source => this.sources.push(source));
    }

    public name() {
        return this.sources[this.sources.length - 1][0];
    }

    public result() {
        return this.sources[this.sources.length - 1][1];
    }
}

export class NamedKey implements Secret {
    constructor(public key: ArrayBuffer, public name: string) {
    }

    public isMatch(buf: ArrayBuffer, store: SecretStore): MatchResult | null {
        if (compareArrayBufs(this.key, buf)) {
            return new MatchResult(this.name, `${str(this.key)}`);
        }
        return null;
    }
}

// a == b
function compareArrayBufs(a: ArrayBuffer, b: ArrayBuffer): boolean {
    const aBytes = new Uint8Array(a, 0);
    const bBytes = new Uint8Array(b, 0);
    if (aBytes.length != bBytes.length) {
        return false;
    }
    for (let i=0; i<aBytes.length; i++) {
        if (aBytes[i] !== bBytes[i]) {
            return false;
        }
    }
    return true;
}

function str(buf: ArrayBuffer, truncate: boolean = true): string {
    if (buf.byteLength === 0) {
        return '{EMPTY}';
    }
    let bytestring = '';
    const bytes = new Uint8Array(buf);
    for (let i=0; i<buf.byteLength; i++) {
        let byte = bytes[i].toString(16);
        if (byte.length === 1) {
            byte = '0' + byte;
        }
        bytestring += byte;
    }
    if (truncate && buf.byteLength > 8) {
        return `0x${bytestring.slice(0, 8)}...${bytestring.slice(-8)}`
    }
    return `0x${bytestring}`;
}

export class HkdfCall implements Secret {
    public result: ArrayBuffer | undefined;
    public name: string;
    constructor(public expansionLen: number, public label: string, public secret: ArrayBuffer) {
        this.name = `hkdf_${label.toLowerCase().replace(/ /g, '_')}`;
    }

    private getSecretMatch(store: SecretStore): MatchResult {
        let secretMatch = store.findMatch(this.secret);
        if (!secretMatch) {
            secretMatch = new MatchResult(`unknown secret`, str(this.secret));
        }
        return secretMatch;
    }

    public isMatch(buf: ArrayBuffer, store: SecretStore): MatchResult | null {
        if (!this.result) {
            return null;
        }

        if (this.expansionLen === 56) {
            const key1 = this.result.slice(0, 0x10);
            const key2 = this.result.slice(0x10, 0x20);
            if (compareArrayBufs(key1, buf)) {
                let match = this.getSecretMatch(store);
                match.push(this.name, `HKDF(${match.name()}, "${this.label}", 56).write_key`);
                return match;
            } else if (compareArrayBufs(key2, buf)) {
                let match = this.getSecretMatch(store);
                match.push(this.name, `HKDF(${match.name()}, "${this.label}", 56).read_key`);
                return match;
            }
        } else if (this.expansionLen === 28) {
            const key = this.result.slice(0, 0x10);
            if (compareArrayBufs(key, buf)) {
                let match = this.getSecretMatch(store);
                match.push(this.name, `HKDF(${match.name()}, "${this.label}", 28).key`);
                return match;
            }
        }
        if (compareArrayBufs(this.result, buf)) {
            let match = this.getSecretMatch(store);
            match.push(this.name, `HKDF(${match.name()}, "${this.label}", ${this.expansionLen})`);
            return match;
        }
        return null;
    }
}

export class EcdhCall implements Secret {
    public result: ArrayBuffer | undefined;
    public name: string;
    constructor(public publicKey: ArrayBuffer, public privateKey: ArrayBuffer) {
        this.name = 'ecdh';
    }

    public isMatch(buf: ArrayBuffer, store: SecretStore): MatchResult | null {
        if (!this.result) {
            return null;
        }

        if (compareArrayBufs(this.result, buf)) {
            let pubMatch = store.findMatch(this.publicKey);
            if (!pubMatch) {
                pubMatch = new MatchResult(`unknown public key`, str(this.publicKey));
            }
            let prvMatch = store.findMatch(this.privateKey);
            if (!prvMatch) {
                prvMatch = new MatchResult(`unknown private key`, str(this.privateKey));
            }
            pubMatch.append(prvMatch)
            pubMatch.push(this.name!, `SHA256(ECDH_compute_key(${pubMatch.name()}, ${prvMatch.name()}))`);
            return pubMatch;
        }
        return null;
    }
}

export class SecretStore {
    public secrets: Secret[];
    private names: {[name: string]: number};
    constructor() {
        this.secrets = [];
        this.names = {};
    }

    public add(secret: Secret): string {
        const numberedName = this.getName(secret.name);
        secret.name = numberedName;
        this.secrets.push(secret);
        return numberedName;
    }

    private getName(name: string): string {
        if (!(name in this.names)) {
            this.names[name] = 0;
        }
        const numberedName = `${name}${this.names[name]}`;
        this.names[name]++;
        return numberedName;
    }

    public findMatch(buf: ArrayBuffer): MatchResult | null {
        for (let secret of this.secrets) {
            const match = secret.isMatch(buf, this);
            if (match) {
                return match;
            }
        }
        return null;
    }
}
