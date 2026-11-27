"use client";

import { twoFactorClient } from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";

let onChallenge: (() => void) | null = null;

export function listenForTwoFactor(handler: () => void) {
  onChallenge = handler;
  return () => {
    if (onChallenge === handler) onChallenge = null;
  };
}

export const authClient = createAuthClient({
  plugins: [
    twoFactorClient({
      onTwoFactorRedirect() {
        onChallenge?.();
      },
    }),
  ],
});
