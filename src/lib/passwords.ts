const COMMON = new Set([
  "password",
  "password1",
  "password12",
  "password123",
  "password1234",
  "password12345",
  "passw0rd",
  "p@ssw0rd",
  "qwerty",
  "qwerty123",
  "qwerty123456",
  "qwertyuiop",
  "123456789012",
  "123456789123",
  "111111111111",
  "letmein",
  "letmein123",
  "welcome",
  "welcome1",
  "welcome123",
  "admin",
  "admin123",
  "admin123456",
  "iloveyou",
  "iloveyou123",
  "changeme",
  "changeme123",
  "secret",
  "secret123",
  "monkey123",
  "dragon123",
  "master123",
  "login123",
  "abc123456789",
  "llaverito",
  "llaverito123",
]);

const WORDS = [
  "password",
  "qwerty",
  "letmein",
  "welcome",
  "admin",
  "iloveyou",
  "princess",
  "monkey",
  "dragon",
  "master",
  "login",
  "passw0rd",
  "changeme",
  "secret",
  "llaverito",
];

const RUNS = ["abcdefghijklmnopqrstuvwxyz", "01234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"];

function isCommonShape(password: string): boolean {
  const lower = password.toLowerCase();
  const stripped = lower.replace(/[^a-z0-9]/g, "");
  if (COMMON.has(lower) || COMMON.has(stripped)) return true;
  const word = stripped.replace(/\d+$/, "");
  const digits = stripped.slice(word.length);
  return WORDS.includes(word) && digits.length > 0 && password.length < 20;
}

function hasRun(password: string): boolean {
  const lower = password.toLowerCase();
  for (let index = 0; index <= lower.length - 6; index += 1) {
    const slice = lower.slice(index, index + 6);
    if (RUNS.some((source) => source.includes(slice))) return true;
  }
  return false;
}

export type PasswordRuleId = "length" | "mix" | "repeat" | "run" | "variety" | "common";
export type PasswordRule = { id: PasswordRuleId; label: string; ok: boolean };

type PasswordCheck = {
  id: PasswordRuleId;
  label: string;
  /** Mensaje de error si la regla falla, o null si se cumple. */
  issue: (password: string) => string | null;
};

// Fuente única de la política: passwordIssues (servidor) y passwordRules (checklist en vivo)
// se derivan de esta lista, así que la UI no puede prometer menos de lo que exige el servidor.
const CHECKS: PasswordCheck[] = [
  {
    id: "length",
    label: "Entre 12 y 128 caracteres",
    issue: (password) =>
      password.length < 12
        ? "Usá al menos 12 caracteres."
        : password.length > 128
          ? "Como máximo 128 caracteres."
          : null,
  },
  {
    id: "mix",
    label: "Letras y números, o una frase de 16+ caracteres con espacios o guiones",
    issue: (password) => {
      const passphrase = password.length >= 16 && /[\s-]/.test(password);
      return !passphrase && (!/[A-Za-z]/.test(password) || !/\d/.test(password))
        ? "Incluí letras y números, o una frase de 16 caracteres o más."
        : null;
    },
  },
  {
    id: "repeat",
    label: "Sin repetir el mismo carácter 8 veces o más",
    issue: (password) => (/(.)\1{7,}/.test(password) ? "Evitá repetir el mismo carácter." : null),
  },
  {
    id: "run",
    label: "Sin secuencias como 123456, abcdef o qwerty",
    issue: (password) => (hasRun(password) ? "Evitá secuencias como 123456 o qwerty." : null),
  },
  {
    id: "variety",
    label: "Si tiene menos de 16 caracteres, al menos 6 caracteres distintos",
    issue: (password) =>
      password.length < 16 && new Set(password.toLowerCase()).size < 6 ? "Usá una contraseña más variada." : null,
  },
  {
    id: "common",
    label: "Que no sea una contraseña común (password123, admin123…)",
    issue: (password) => (isCommonShape(password) ? "Es una contraseña demasiado común." : null),
  },
];

/** Checklist en vivo para el alta: refleja exactamente la política de passwordIssues. */
export function passwordRules(password: string): PasswordRule[] {
  return CHECKS.map((check) => ({ id: check.id, label: check.label, ok: check.issue(password) === null }));
}

export function passwordIssues(password: string): string[] {
  const issues: string[] = [];
  for (const check of CHECKS) {
    const issue = check.issue(password);
    if (issue) issues.push(issue);
  }
  return issues;
}

export function isStrongPassword(password: string): boolean {
  return passwordIssues(password).length === 0;
}

const LABELS = ["Vacía", "Débil", "Aceptable", "Buena", "Fuerte"] as const;

export function passwordStrength(password: string): { score: 0 | 1 | 2 | 3 | 4; label: (typeof LABELS)[number] } {
  if (!password) return { score: 0, label: "Vacía" };
  const issues = passwordIssues(password);
  let score = 1;
  if (password.length >= 12) score += 1;
  if (password.length >= 18) score += 1;
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((pattern) => pattern.test(password)).length;
  if (classes >= 3) score += 1;
  if (issues.length > 0) score = 1;
  const clamped = Math.max(0, Math.min(4, score)) as 0 | 1 | 2 | 3 | 4;
  return { score: clamped, label: LABELS[clamped] };
}
