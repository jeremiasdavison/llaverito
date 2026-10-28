import type { Access } from "./types";

const rank: Record<Access, number> = {
  none: 0,
  use: 1,
  admin: 2,
  owner: 3,
};

export function maxAccess(left: Access, right: Access): Access {
  return rank[left] >= rank[right] ? left : right;
}

export function canAdminister(access: Access): boolean {
  return access === "owner" || access === "admin";
}

export function canUse(access: Access): boolean {
  return access !== "none";
}
