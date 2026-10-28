export type Actor = {
  id: string;
  email: string;
  name: string;
};

export type Access = "owner" | "admin" | "use" | "none";

export type ItemKind = "api_key" | "ssh_key";
export type FolderKind = "personal" | "project";
export type SharePermission = "use" | "admin";
