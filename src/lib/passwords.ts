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

export function passwordIssues(password: string): string[] {
  const issues: string[] = [];
  if (password.length < 12) issues.push("Usá al menos 12 caracteres.");
  if (password.length > 128) issues.push("Como máximo 128 caracteres.");
  const passphrase = password.length >= 16 && /[\s-]/.test(password);
  if (!passphrase && (!/[A-Za-z]/.test(password) || !/\d/.test(password))) {
    issues.push("Incluí letras y números, o una frase de 16 caracteres o más.");
  }
  if (/(.)\1{7,}/.test(password)) issues.push("Evitá repetir el mismo carácter.");
  if (hasRun(password)) issues.push("Evitá secuencias como 123456 o qwerty.");
  if (password.length < 16 && new Set(password.toLowerCase()).size < 6) {
    issues.push("Usá una contraseña más variada.");
  }
  if (isCommonShape(password)) issues.push("Es una contraseña demasiado común.");
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
