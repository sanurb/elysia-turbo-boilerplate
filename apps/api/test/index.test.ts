import { describe, expect, it } from "bun:test";
import app from "../src/index";

describe("Elysia", () => {
    it("should return a response", async () => {
        const response = await app
            .handle(new Request("http://localhost:3000/health"))
            .then(res => res.text());

        expect(response).toBe("OK");
    });

    // testing auth routes
    it("should return a response", async () => {
        const response = await app
            .handle(new Request("http://localhost:3000/auth/api/ok"))
            .then(res => res.json());

        expect(response).toEqual({ ok: true });
    });
});
