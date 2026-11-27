"use client";

import { useCallback, useEffect, useRef, useState } from "react";

const HIDE_AFTER_MS = 20_000;
const HIDE_AFTER_COPY_MS = 10_000;

export function useEphemeralSecret() {
  const [secret, setSecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [secondsLeft, setSecondsLeft] = useState(0);
  const secretRef = useRef<string | null>(null);
  const deadlineRef = useRef(0);
  const timerRef = useRef<number | null>(null);

  const stop = useCallback(() => {
    if (timerRef.current !== null) {
      window.clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const clear = useCallback(() => {
    stop();
    secretRef.current = null;
    deadlineRef.current = 0;
    setSecret(null);
    setCopied(false);
    setSecondsLeft(0);
  }, [stop]);

  const tick = useCallback(() => {
    const left = deadlineRef.current - Date.now();
    if (left <= 0) {
      clear();
      return;
    }
    setSecondsLeft(Math.ceil(left / 1000));
  }, [clear]);

  const arm = useCallback(
    (ms: number) => {
      deadlineRef.current = Date.now() + ms;
      setSecondsLeft(Math.ceil(ms / 1000));
      stop();
      timerRef.current = window.setInterval(tick, 250);
    },
    [stop, tick],
  );

  const reveal = useCallback(
    (value: string) => {
      secretRef.current = value;
      setSecret(value);
      setCopied(false);
      arm(HIDE_AFTER_MS);
    },
    [arm],
  );

  const copy = useCallback(async () => {
    const value = secretRef.current;
    if (!value) throw new Error("No se pudo copiar");
    let wrote = false;
    if (navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(value);
        wrote = true;
      } catch {
        wrote = false;
      }
    }
    if (!wrote) {
      const field = document.createElement("textarea");
      field.value = value;
      field.setAttribute("readonly", "");
      field.style.position = "fixed";
      field.style.left = "-9999px";
      document.body.appendChild(field);
      field.focus();
      field.select();
      wrote = document.execCommand("copy");
      field.value = "";
      field.remove();
    }
    if (!wrote) throw new Error("No se pudo copiar");
    setCopied(true);
    const left = deadlineRef.current - Date.now();
    if (left > HIDE_AFTER_COPY_MS) arm(HIDE_AFTER_COPY_MS);
  }, [arm]);

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) window.clearInterval(timerRef.current);
      secretRef.current = null;
    };
  }, []);

  return { secret, copied, secondsLeft, reveal, copy, clear };
}
