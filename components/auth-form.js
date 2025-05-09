"use client";
import { signup } from '@/actions/auth-action';
import Link from 'next/link';
import { useFormState } from 'react-dom';

export default function AuthForm() {
  const [formState , formAction , isPending] = useFormState(signup , {});
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
        <ul id='form-errors'>
          {Object.keys(formState.errors).map((error) => (
            <li key={error}>{formState.errors[error]}</li>
          ))}
        </ul>
      )}
      <p>
        <button disabled={isPending} type="submit">
          {isPending ? "is submitting" : "create account"}
        </button>
      </p>
      <p>
        <Link href="/">Login with existing account.</Link>
      </p>
    </form>
  );
}
