export function isStrongPassword(password: string): boolean {
  return (
    password.length >= 12 &&
    password.length <= 128 &&
    /[A-Za-z]/.test(password) &&
    /\d/.test(password)
  );
}
