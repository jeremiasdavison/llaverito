export type PasswordRule = { id: "length" | "letter" | "number"; label: string; ok: boolean };

export function passwordRules(password: string): PasswordRule[] {
  return [
    { id: "length", label: "Entre 12 y 128 caracteres", ok: password.length >= 12 && password.length <= 128 },
    { id: "letter", label: "Al menos una letra", ok: /[A-Za-z]/.test(password) },
    { id: "number", label: "Al menos un número", ok: /\d/.test(password) },
  ];
}

export function isStrongPassword(password: string): boolean {
  return passwordRules(password).every((rule) => rule.ok);
}
