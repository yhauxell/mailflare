import bcrypt from "bcryptjs";
import { newId } from "@/lib/ids";

const KEY_PREFIX = "ep_";

export async function hashApiKey(key: string): Promise<string> {
	const encoder = new TextEncoder();
	const digest = await crypto.subtle.digest("SHA-256", encoder.encode(key));
	return Array.from(new Uint8Array(digest))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

export async function generateApiKey(): Promise<{ fullKey: string; prefix: string; hash: string }> {
	const secret = newId();
	const fullKey = `${KEY_PREFIX}${secret}`;
	const prefix = fullKey.slice(0, 12);
	const hash = await hashApiKey(fullKey);
	return { fullKey, prefix, hash };
}

export async function verifyApiKey(fullKey: string, hash: string): Promise<boolean> {
	if (!hash) return false;
	if (hash.startsWith("$2a$") || hash.startsWith("$2b$") || hash.startsWith("$2y$")) {
		return bcrypt.compareSync(fullKey, hash);
	}
	const computed = await hashApiKey(fullKey);
	return computed === hash;
}

export function parseScopes(scopesJson: string): string[] {
	try {
		const parsed = JSON.parse(scopesJson) as unknown;
		return Array.isArray(parsed) ? parsed.filter((s): s is string => typeof s === "string") : [];
	} catch {
		return [];
	}
}

export function scopesToJson(scopes: string[]): string {
	return JSON.stringify(scopes);
}
