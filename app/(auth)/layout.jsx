import { logout } from "@/actions/auth-action";
import "./globals.css";

const AuthLayout = ({ children }) => {
  return (
    <>
      <header id="auth-header">
        <p>Welcome back!</p>
        <form action={logout}>
          <button>Logout</button>
        </form>
      </header>
      {children}
    </>
  );
};

export default AuthLayout;
