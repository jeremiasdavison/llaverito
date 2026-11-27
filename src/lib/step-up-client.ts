type Challenge = { twoFactor: boolean };
type Prompt = (input: Challenge) => Promise<boolean>;

let prompt: Prompt | null = null;

export function registerStepUpPrompt(next: Prompt) {
  prompt = next;
  return () => {
    if (prompt === next) prompt = null;
  };
}

export async function requestStepUp(input: Challenge) {
  if (!prompt) throw new Error("Confirmá tu identidad en Seguridad e intentá de nuevo.");
  const accepted = await prompt(input);
  if (!accepted) throw new Error("Se canceló la confirmación.");
}
