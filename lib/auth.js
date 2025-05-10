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
  cookies().set(session.name, session.value, session.attribute);
};

export async function createAuthSession(userId) {
  const session = lucia.createSession(userId, {});
  const sessionCookie = lucia.createBlankSessionCookie(session.id);
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
  if (result.session && result.session.fresh) {
    const sessionCookie = lucia.createSessionCookie(result.session.id);
    handleSetCookies(sessionCookie);
  }
  if (!result.session) {
    const sessionCookie = lucia.createBlankSessionCookie();
    handleSetCookies(sessionCookie);
  }

  return result;
}

export async function destroySession() {
  const { session } = verifyAuth();
  if (!session) {
    return {
      error: "Unauthorized !",
    };
  }

  await lucia.invalidateSession(session.id);
  const sessionCookie = lucia.createBlankSessionCookie();
  handleSetCookies(sessionCookie);
}
