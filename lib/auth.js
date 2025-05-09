import { Lucia } from "lucia";
import { BetterSqlite3Adapter } from "@lucia-auth/adapter-sqlite";
import db from "./db";
import { cookies } from "next/headers";

const adapter = new BetterSqlite3Adapter(db, {
  user: "users",
  session: "sessions",
});

const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    attributes: {
      secure: process.env.NODE_ENV === "production",
    },
  },
});

const handleSetCookies = (session) => {
    cookies().set(
        session.name,
        session.value,
        session.attributes
    )
}

export async function createAuthSession(userId) {
  const session = await lucia.createSession(userId, {});
  const sessionCookie = lucia.createSessionCookie(session.id);
  handleSetCookies(sessionCookie);
}

export async function verifyAuth() {
  const sessionCookie = cookies().get(lucia.sessionCookieName);
  if (!sessionCookie) {
    return {
      user: null,
      session: null,
    };
  }
  const sessionId = sessionCookie.value;
  if (!sessionId) {
    return {
      user: null,
      session: null,
    };
  }
  const result = await lucia.validateSession(sessionId);
  try {
    if (result.session && result.session.fresh) {
      const sessionCookie = lucia.createSessionCookie(result.session.id);
      handleSetCookies(sessionCookie)
    }
    if(!result.session) {
        const sessionCookie = lucia.createBlankSessionCookie(); // clear the existing cookie which contains invalid values
        handleSetCookies(sessionCookie);
    }
  } catch {} // next js doesn let us set cookies white rendering pages that is why left the catch error empty

  return result;
}
