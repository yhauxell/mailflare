import bcrypt from "bcryptjs";

const PBKDF2_ITERATIONS = 5000;

export async function hashPassword(password: string): Promise<string> {
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const encoder = new TextEncoder();
	const keyMaterial = await crypto.subtle.importKey(
		"raw",
		encoder.encode(password),
		{ name: "PBKDF2" },
		false,
		["deriveBits"],
	);
	const derivedBits = await crypto.subtle.deriveBits(
		{
			name: "PBKDF2",
			salt,
			iterations: PBKDF2_ITERATIONS,
			hash: "SHA-256",
		},
		keyMaterial,
		256,
	);
	const hashHex = Array.from(new Uint8Array(derivedBits))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
	const saltHex = Array.from(salt)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
	return `pbkdf2:${PBKDF2_ITERATIONS}:${saltHex}:${hashHex}`;
}

export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
	if (!storedHash) return false;

	// Backward compatibility with existing bcrypt hashes
	if (storedHash.startsWith("$2a$") || storedHash.startsWith("$2b$") || storedHash.startsWith("$2y$")) {
		return bcrypt.compareSync(password, storedHash);
	}

	// Native Web Crypto PBKDF2
	if (storedHash.startsWith("pbkdf2:")) {
		const parts = storedHash.split(":");
		if (parts.length !== 4) return false;
		const iterations = parseInt(parts[1], 10);
		const saltHex = parts[2];
		const expectedHashHex = parts[3];

		const salt = new Uint8Array(saltHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16)));
		const encoder = new TextEncoder();
		const keyMaterial = await crypto.subtle.importKey(
			"raw",
			encoder.encode(password),
			{ name: "PBKDF2" },
			false,
			["deriveBits"],
		);
		const derivedBits = await crypto.subtle.deriveBits(
			{
				name: "PBKDF2",
				salt,
				iterations,
				hash: "SHA-256",
			},
			keyMaterial,
			256,
		);
		const hashHex = Array.from(new Uint8Array(derivedBits))
			.map((b) => b.toString(16).padStart(2, "0"))
			.join("");

		return hashHex === expectedHashHex;
	}

	return false;
}
