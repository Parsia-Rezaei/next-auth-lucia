"use client";
import { auth, signup } from "@/actions/auth-action";
import Link from "next/link";
import { useFormState } from "react-dom";

export default function AuthForm({ mode }) {
  const [formState, formAction, isPending] = useFormState(auth.bind(null , mode) , {});
  return (
    <form action={formAction} id="auth-form">
      <div>
        <img src="/images/auth-icon.jpg" alt="A lock icon" />
      </div>
      <p>
        <label htmlFor="email">Email</label>
        <input type="email" name="email" id="email" />
      </p>
      <p>
        <label htmlFor="password">Password</label>
        <input type="password" name="password" id="password" />
      </p>
      {formState.errors && (
        <ul id="form-errors">
          {Object.keys(formState.errors).map((error) => (
            <li key={error}>{formState.errors[error]}</li>
          ))}
        </ul>
      )}
      <p>
        <button type="submit">
          {mode === "login" ? "Login" : "singup"}
        </button>
      </p>
      <p>
        {mode === "login" && (
          <Link href="/?mode=signup">Create an account</Link>
        )}
        {mode === "signup" && (
          <Link href="/?mode=login">Login with existing account</Link>
        )}
      </p>
    </form>
  );
}
